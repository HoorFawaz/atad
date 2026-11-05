# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Runs the LOG module: live export on Windows, or import of copied .evtx files."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from atad.adapters.base import ParseContext
from atad.adapters.catalog import EvtxRust, PythonEvtx, Sysmon, Wevtutil
from atad.cases.manager import OpenCase
from atad.core.execution import execute_to_file, import_file, record_skipped
from atad.core.platform import WINDOWS, current_os, local_hostname
from atad.evidence.models import (
    CollectionMode,
    Evidence,
    Execution,
    ExecutionStatus,
    SourceModule,
)
from atad.modules.logs.evtx_reader import (
    DEFAULT_MAX_EVENTS,
    ReadStats,
    is_evtx,
    iter_evtx_xml,
    parse_event_xml,
)
from atad.modules.logs.mapping import SECURITY, SUPPORTED, SYSMON, event_to_evidence, is_supported
from atad.utils.validation import validate_source_host

CHECKS = ["security", "sysmon"]
CHANNEL_FOR_CHECK = {"security": SECURITY, "sysmon": SYSMON}

DEFAULT_HOURS = 24
MAX_HOURS = 24 * 90


@dataclass
class SourceOutcome:
    """Result for one log source (a live channel or one imported file)."""

    name: str
    execution: Execution
    evidence: list[Evidence] = field(default_factory=list)
    stats: ReadStats | None = None
    unsupported: Counter = field(default_factory=Counter)
    computers: set[str] = field(default_factory=set)


@dataclass
class LogRunResult:
    case: OpenCase
    host: str
    collection_mode: CollectionMode
    outcomes: list[SourceOutcome] = field(default_factory=list)

    @property
    def evidence(self) -> list[Evidence]:
        return [e for o in self.outcomes for e in o.evidence]


# --------------------------------------------------------------------------- #
# Parsing a stored .evtx copy into evidence
# --------------------------------------------------------------------------- #


def _parse_into_case(case: OpenCase, outcome: SourceOutcome, evtx_path: Path,
                     ctx: ParseContext, max_events: int) -> None:
    stats = ReadStats()
    batch: list[Evidence] = []
    try:
        for xml in iter_evtx_xml(evtx_path, stats, max_events):
            event = parse_event_xml(xml)
            if event is None:
                stats.record_errors += 1
                continue
            if event.get("computer"):
                outcome.computers.add(event["computer"])
            if not is_supported(event):
                outcome.unsupported[f"{event.get('channel')}:{event.get('event_id')}"] += 1
                continue
            ev = event_to_evidence(event, ctx)
            if ev is not None:
                batch.append(ev)
    except Exception as exc:  # unreadable/corrupted file
        stats.errors.append(f"could not read file: {exc}")
    if stats.records_read == 0 and not stats.errors:
        # A parser may return nothing for a damaged file; never let that look
        # like a clean log.
        stats.errors.append("no records could be read — the log is empty, cleared or damaged")
    # Store in time order so evidence ids follow the timeline.
    batch.sort(key=lambda e: (e.event_time is None, e.event_time))
    outcome.evidence = case.repo.add_evidence_many(batch)
    outcome.stats = stats


def parser_tool() -> tuple[str, str | None]:
    """(name, version) of the EVTX parser that will be used."""
    for adapter in (EvtxRust(), PythonEvtx()):
        info = adapter.detect()
        if info.available:
            return adapter.name, info.version
    return "evtx", None


def _ctx(case: OpenCase, ex: Execution, host: str, mode: CollectionMode, declared: bool,
         version: str | None, tool: str = "evtx") -> ParseContext:
    return ParseContext(
        case_id=case.case.id, host=host, collection_mode=mode, host_declared=declared,
        execution_id=ex.id, raw_ref=ex.raw_ref, raw_sha256=ex.raw_sha256,
        tool_version=version, simulated=case.case.simulated, tool=tool,
    )


# --------------------------------------------------------------------------- #
# Import mode
# --------------------------------------------------------------------------- #


def find_evtx_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*")
                  if p.is_file() and not p.is_symlink() and p.suffix.lower() == ".evtx")


def run_log_import(case: OpenCase, path: Path, source_host: str,
                   max_events: int = DEFAULT_MAX_EVENTS) -> LogRunResult:
    """Import .evtx files copied from another machine."""
    host = validate_source_host(source_host)
    mode = CollectionMode.IMPORT
    result = LogRunResult(case=case, host=host, collection_mode=mode)
    tool, version = parser_tool()

    for src in find_evtx_files(path):
        if not is_evtx(src):
            ex = record_skipped(case, module=SourceModule.LOG, tool=tool,
                                collection_mode=mode, status=ExecutionStatus.UNAVAILABLE,
                                reason=f"not a valid .evtx file: {src}", target=host)
            result.outcomes.append(SourceOutcome(src.name, ex))
            continue
        rec = import_file(case, module=SourceModule.LOG, tool=tool, source=src,
                          tool_version=version, target=host)
        outcome = SourceOutcome(src.name, rec.execution)
        if rec.raw_path is not None and rec.execution.status is ExecutionStatus.SUCCESS:
            _parse_into_case(case, outcome, rec.raw_path,
                             _ctx(case, rec.execution, host, mode, True, version, tool), max_events)
        result.outcomes.append(outcome)
    return result


# --------------------------------------------------------------------------- #
# Live mode (Windows)
# --------------------------------------------------------------------------- #


def build_xpath(event_ids: set[int], hours: int) -> str:
    """XPath filter for wevtutil: supported event ids within the last N hours."""
    ids = " or ".join(f"EventID={i}" for i in sorted(event_ids))
    ms = hours * 3600 * 1000
    return f"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"


def build_export_args(wevtutil: str, channel: str, out: Path, hours: int) -> list[str]:
    return [
        wevtutil, "epl", channel, str(out),
        f"/q:{build_xpath(SUPPORTED[channel], hours)}",
        "/ow:false",
    ]


def run_log_live(case: OpenCase, checks: list[str], *, excluded: list[str] | None = None,
                 hours: int = DEFAULT_HOURS, max_events: int = DEFAULT_MAX_EVENTS) -> LogRunResult:
    """Export Security/Sysmon logs from this machine and parse them."""
    if not 1 <= hours <= MAX_HOURS:
        from atad.core.exceptions import ValidationError
        raise ValidationError(f"--hours must be between 1 and {MAX_HOURS}")

    host = local_hostname()
    mode = CollectionMode.LOCAL
    result = LogRunResult(case=case, host=host, collection_mode=mode)
    excluded = excluded or []
    tool, version = parser_tool()
    on_windows = current_os() == WINDOWS
    wevtutil = Wevtutil().detect() if on_windows else None

    for check in CHECKS:
        channel = CHANNEL_FOR_CHECK[check]
        if check in excluded:
            ex = record_skipped(case, module=SourceModule.LOG, tool="wevtutil",
                                collection_mode=mode, status=ExecutionStatus.SKIPPED,
                                reason="excluded_by_user", target=channel)
            result.outcomes.append(SourceOutcome(check, ex))
            continue
        if check not in checks:
            continue
        reason = None
        if not on_windows:
            reason = (f"live Windows log collection is not available on {current_os()} "
                      "(use `atad log import`; Linux logs come in M9)")
        elif not wevtutil or not wevtutil.available:
            reason = "wevtutil not found"
        elif check == "sysmon" and not Sysmon().detect().available:
            reason = "Sysmon is not installed on this machine"
        if reason:
            ex = record_skipped(case, module=SourceModule.LOG, tool="wevtutil",
                                collection_mode=mode, status=ExecutionStatus.UNAVAILABLE,
                                reason=reason, target=channel)
            result.outcomes.append(SourceOutcome(check, ex))
            continue

        rec = execute_to_file(
            case, module=SourceModule.LOG, tool=f"wevtutil_{check}", collection_mode=mode,
            build_args=lambda out, ch=channel: build_export_args(wevtutil.path, ch, out, hours),
            out_suffix="evtx", target=channel,
        )
        outcome = SourceOutcome(check, rec.execution)
        if rec.raw_path is not None and rec.execution.status is ExecutionStatus.SUCCESS:
            _parse_into_case(case, outcome, rec.raw_path,
                             _ctx(case, rec.execution, host, mode, False, version, tool), max_events)
        result.outcomes.append(outcome)
    return result


# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #


def search_logs(case: OpenCase, keyword: str) -> list[Evidence]:
    """Search stored log evidence by a named keyword or by free text."""
    from atad.modules.logs.mapping import KEYWORDS
    import json

    kw = keyword.strip().lower()
    if not kw:
        from atad.core.exceptions import ValidationError
        raise ValidationError("keyword is empty")
    logs = [e for e in case.repo.list_evidence() if e.source_module is SourceModule.LOG]
    if kw in KEYWORDS:
        wanted = KEYWORDS[kw]
        hits = [e for e in logs if (e.data.get("channel"), e.data.get("event_id")) in wanted]
    else:
        hits = [e for e in logs
                if kw in e.summary.lower() or kw in json.dumps(e.data, ensure_ascii=False).lower()]
    return sorted(hits, key=lambda e: (e.event_time is None, e.event_time, e.id))


def summarize(outcome: SourceOutcome) -> dict[str, Any]:
    by_event = Counter(f"{'Security' if e.data['channel'] == SECURITY else 'Sysmon'} {e.data['event_id']}"
                       for e in outcome.evidence)
    return {"by_event": dict(sorted(by_event.items()))}
