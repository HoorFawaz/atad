# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Linux side of the LOG module.

Live (on the machine itself, as root):
* ``auth``    — copies /var/log/auth.log (Debian/Ubuntu) or /var/log/secure
               (RHEL/Fedora) and the previous rotation (``.1``) into the case.
* ``journal`` — ``journalctl -o json`` for sshd, sudo, useradd and systemd
               over the last --hours.
* ``audit``   — copies /var/log/audit/audit.log (auditd).

Import: auth/secure/syslog files, journal JSON exports and audit.log copied
from another machine; the format is detected from the content.
"""

from __future__ import annotations

import shutil
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from pathlib import Path

from atad.cases.manager import OpenCase
from atad.core.exceptions import ValidationError
from atad.core.execution import execute_and_record, import_file, record_skipped
from atad.core.progress import track
from atad.evidence.models import CollectionMode, Evidence, ExecutionStatus, SourceModule, utc_now
from atad.modules.logs import linux as lx
from atad.modules.logs.evtx_reader import ReadStats

LINUX_CHECKS = ["auth", "journal", "audit"]
AUTH_FILES = ("/var/log/auth.log", "/var/log/secure")
AUDIT_FILE = "/var/log/audit/audit.log"
JOURNAL_IDENTIFIERS = ("sshd", "sshd-session", "sudo", "useradd", "systemd")
JOURNAL_MAX_OUTPUT = 512 * 1024 * 1024


def parse_timezone(value: str | None) -> tuple[tzinfo, str]:
    """'UTC', '+03:00', '-0500' or an IANA name such as 'Asia/Riyadh'."""
    v = (value or "UTC").strip()
    if v.upper() in ("UTC", "Z"):
        return UTC, "UTC"
    import re
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})?", v)
    if m:
        delta = timedelta(hours=int(m[2]), minutes=int(m[3] or 0))
        return timezone(delta if m[1] == "+" else -delta), v
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        return ZoneInfo(v), v
    except (ZoneInfoNotFoundError, ValueError):
        raise ValidationError(f"unknown time zone {v!r} (use UTC, +03:00 or a name like Asia/Riyadh)") from None


def local_timezone() -> tuple[tzinfo, str]:
    tz = datetime.now().astimezone().tzinfo or UTC
    return tz, f"{datetime.now().astimezone().strftime('%z')} (this machine)"


def _mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)


def parse_file(path: Path, fmt: str, *, file_mtime: datetime, tz: tzinfo, tz_label: str,
               host: str | None, stats: lx.SyslogStats) -> Iterator[lx.LinuxRecord]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if fmt == "journal":
        return lx.iter_journal(text, stats)
    if fmt == "audit":
        return lx.iter_audit(text, stats, host=host)
    return lx.iter_syslog(text, file_mtime=file_mtime, tz=tz, tz_label=tz_label, stats=stats)


def to_read_stats(st: lx.SyslogStats, truncated: bool, empty_note: str | None = None) -> ReadStats:
    rs = ReadStats(records_read=st.lines, record_errors=st.unparsed, truncated=truncated,
                   engine="atad-linux")
    if st.lines == 0:
        rs.errors.append(empty_note or "no lines could be read — the log is empty or unreadable")
    if st.assumed_times:
        rs.errors.append(f"{st.assumed_times} line(s) have no year or time zone; "
                         "the year comes from the file date and the zone from --timezone")
    return rs


def store_records(case: OpenCase, outcome, records: Iterator[lx.LinuxRecord], ctx, *,
                  since: datetime | None, max_events: int, stats: lx.SyslogStats,
                  empty_note: str | None = None) -> None:
    """Convert, filter by time window, store in time order."""
    batch: list[Evidence] = []
    truncated = False
    for rec in track(records, "reading log records"):
        if rec.host:
            outcome.computers.add(rec.host)
        if since and rec.time and rec.time < since:
            continue
        if len(batch) >= max_events:
            truncated = True
            break
        batch.append(lx.record_to_evidence(rec, ctx))
    batch.sort(key=lambda e: (e.event_time is None, e.event_time))
    outcome.evidence = case.repo.add_evidence_many(batch)
    outcome.unsupported = Counter({"other lines": stats.unsupported}) if stats.unsupported else Counter()
    outcome.stats = to_read_stats(stats, truncated, empty_note)


# --------------------------------------------------------------------------- live


def _readable(path: str) -> bool:
    import os
    return os.path.isfile(path) and os.access(path, os.R_OK)


def run_linux_live(case: OpenCase, result, checks: list[str], excluded: list[str],
                   hours: int, max_events: int, ctx_for, source_outcome) -> None:
    """Fill ``result`` (a LogRunResult) with the Linux live sources."""
    mode = CollectionMode.LOCAL
    since = utc_now() - timedelta(hours=hours)
    tz, tz_label = local_timezone()

    for check in LINUX_CHECKS:
        if check in excluded:
            ex = record_skipped(case, module=SourceModule.LOG, tool=check, collection_mode=mode,
                                status=ExecutionStatus.SKIPPED, reason="excluded_by_user", target=check)
            result.outcomes.append(source_outcome(check, ex))
            continue
        if check not in checks:
            continue

        if check == "journal":
            exe = shutil.which("journalctl")
            if not exe:
                ex = record_skipped(case, module=SourceModule.LOG, tool="journalctl", collection_mode=mode,
                                    status=ExecutionStatus.UNAVAILABLE,
                                    reason="journalctl not found (no systemd journal)", target="journal")
                result.outcomes.append(source_outcome(check, ex))
                continue
            args = [exe, "-o", "json", "--no-pager", "--since",
                    since.strftime("%Y-%m-%d %H:%M:%S UTC")]
            for ident in JOURNAL_IDENTIFIERS:
                args.append(f"SYSLOG_IDENTIFIER={ident}")
            rec = execute_and_record(case, module=SourceModule.LOG, tool="journalctl", args=args,
                                     collection_mode=mode, target="journal",
                                     max_output=JOURNAL_MAX_OUTPUT)
            outcome = source_outcome(check, rec.execution)
            if rec.raw_path is not None and rec.execution.status is ExecutionStatus.SUCCESS:
                st = lx.SyslogStats()
                store_records(case, outcome, lx.iter_journal(rec.raw_path.read_text("utf-8", "replace"), st),
                              ctx_for(rec.execution, "journalctl"), since=since,
                              max_events=max_events, stats=st,
                              empty_note=f"no sshd, sudo, useradd or systemd entries in the last {hours} hour(s)")
            result.outcomes.append(outcome)
            continue

        sources = ([p for p in AUTH_FILES for p in (p, p + ".1")] if check == "auth" else [AUDIT_FILE])
        present = [p for p in sources if Path(p).is_file()]
        if not present:
            reason = ("no /var/log/auth.log or /var/log/secure (this system may log only to the journal)"
                      if check == "auth" else "auditd log not found (/var/log/audit/audit.log)")
            ex = record_skipped(case, module=SourceModule.LOG, tool=check, collection_mode=mode,
                                status=ExecutionStatus.UNAVAILABLE, reason=reason, target=check)
            result.outcomes.append(source_outcome(check, ex))
            continue
        for src in present:
            if not _readable(src):
                ex = record_skipped(case, module=SourceModule.LOG, tool=check, collection_mode=mode,
                                    status=ExecutionStatus.UNAVAILABLE,
                                    reason=f"permission denied reading {src} — run atad as root",
                                    target=src)
                result.outcomes.append(source_outcome(f"{check} ({Path(src).name})", ex))
                continue
            p = Path(src)
            mtime = _mtime(p)
            rec = import_file(case, module=SourceModule.LOG, tool=f"{check}-log", source=p,
                              collection_mode=mode, target=src)
            outcome = source_outcome(f"{check} ({p.name})", rec.execution)
            if rec.raw_path is not None and rec.execution.status is ExecutionStatus.SUCCESS:
                st = lx.SyslogStats()
                fmt = "audit" if check == "audit" else "syslog"
                records = parse_file(rec.raw_path, fmt, file_mtime=mtime, tz=tz, tz_label=tz_label,
                                     host=None, stats=st)
                store_records(case, outcome, records, ctx_for(rec.execution, f"{check}-log"),
                              since=since, max_events=max_events, stats=st)
            result.outcomes.append(outcome)


# --------------------------------------------------------------------------- import


def import_linux_file(case: OpenCase, result, src: Path, fmt: str, *, host: str,
                      tz: tzinfo, tz_label: str, max_events: int, ctx_for, source_outcome) -> None:
    mtime = _mtime(src)
    tool = {"journal": "journal-json", "audit": "audit-log", "syslog": "syslog"}[fmt]
    rec = import_file(case, module=SourceModule.LOG, tool=tool, source=src, target=host)
    outcome = source_outcome(src.name, rec.execution)
    if rec.raw_path is not None and rec.execution.status is ExecutionStatus.SUCCESS:
        st = lx.SyslogStats()
        records = parse_file(rec.raw_path, fmt, file_mtime=mtime, tz=tz, tz_label=tz_label,
                             host=None, stats=st)
        store_records(case, outcome, records, ctx_for(rec.execution, tool), since=None,
                      max_events=max_events, stats=st)
    result.outcomes.append(outcome)
