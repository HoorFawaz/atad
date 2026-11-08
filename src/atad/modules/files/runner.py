# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Runs the FILES module checks for a case and stores their evidence."""

from __future__ import annotations

import json
import os
import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from atad.adapters.base import ParseContext
from atad.adapters.catalog import YaraPython
from atad.cases.manager import OpenCase
from atad.core.execution import execute_collector, record_skipped
from atad.core.platform import local_hostname
from atad.evidence.models import (
    CollectionMode,
    Evidence,
    Execution,
    ExecutionStatus,
    SourceModule,
)
from atad.modules.files import collector as fc
from atad.utils.validation import validate_source_host

CHECKS = ["hash", "info", "scan"]

TOOL_FOR_CHECK = {"hash": "hashlib", "info": "os.stat", "scan": "yara-python"}


def default_rules_path() -> Path:
    """Where YARA rules are looked for when ``--rules`` is not given.

    1. ``ATAD_RULES`` environment variable
    2. ``./rules`` in the current folder
    3. ``rules/`` next to the atad executable (release package layout)
    """
    import sys

    if os.environ.get("ATAD_RULES"):
        return Path(os.environ["ATAD_RULES"])
    here = Path("rules")
    if here.is_dir():
        return here
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "rules"
    return here


@dataclass
class CheckOutcome:
    check: str
    execution: Execution
    evidence: list[Evidence] = field(default_factory=list)
    capture: dict[str, Any] | None = None


@dataclass
class FilesRunResult:
    case: OpenCase
    path: Path
    host: str
    collection_mode: CollectionMode
    outcomes: list[CheckOutcome] = field(default_factory=list)

    def outcome(self, check: str) -> CheckOutcome | None:
        return next((o for o in self.outcomes if o.check == check), None)

    @property
    def evidence(self) -> list[Evidence]:
        return [e for o in self.outcomes for e in o.evidence]


def run_files(
    case: OpenCase,
    path: Path,
    checks: list[str],
    *,
    excluded: list[str] | None = None,
    source_host: str | None = None,
    rules: Path | None = None,
    max_files: int = fc.DEFAULT_MAX_FILES,
) -> FilesRunResult:
    """Run the selected file checks on ``path`` and store everything in ``case``."""
    if source_host:
        mode, host, declared = CollectionMode.IMPORT, validate_source_host(source_host), True
    else:
        mode, host, declared = CollectionMode.LOCAL, local_hostname(), False

    result = FilesRunResult(case=case, path=path, host=host, collection_mode=mode)
    excluded = excluded or []

    py_version = platform.python_version()
    # Never collect atad's own case folders as evidence.
    exclude = (case.path.parent,)

    def run(check: str, tool: str, version: str | None,
            collect: Callable[[], dict], to_evidence: Callable[[dict, ParseContext], list[Evidence]]) -> None:
        rec = execute_collector(
            case,
            module=SourceModule.FILES,
            tool=tool,
            tool_version=version,
            collection_mode=mode,
            target=str(path),
            description=[check, str(path)],
            collect=lambda: json.dumps(collect(), ensure_ascii=False, indent=2).encode("utf-8"),
        )
        outcome = CheckOutcome(check, rec.execution)
        if rec.raw is not None:
            capture = json.loads(rec.raw)
            ctx = ParseContext(
                case_id=case.case.id,
                host=host,
                collection_mode=mode,
                host_declared=declared,
                execution_id=rec.execution.id,
                raw_ref=rec.execution.raw_ref,
                raw_sha256=rec.execution.raw_sha256,
                tool_version=version,
                simulated=case.case.simulated,
            )
            outcome.capture = capture
            outcome.evidence = case.repo.add_evidence_many(to_evidence(capture, ctx))
        result.outcomes.append(outcome)

    # The folder is listed once, and when both hash and scan run, each file is
    # read once for both (big folders take half the time).
    walk_cache: dict[str, fc.WalkResult] = {}

    def walk() -> fc.WalkResult:
        if "w" not in walk_cache:
            walk_cache["w"] = fc.walk_files(path, max_files, exclude)
        return walk_cache["w"]

    scan_plan = _scan_plan(path, rules) if "scan" in checks and "scan" not in excluded else None
    together = "hash" in checks and "hash" not in excluded and scan_plan is not None \
        and scan_plan[0] is not None
    pending_scan: dict[str, dict] = {}

    def hash_collect() -> dict:
        if together:
            try:
                compiled = fc.compile_rules(scan_plan[0])
            except Exception:  # noqa: BLE001 - bad rules: the scan check reports it on its own
                compiled = None
            if compiled is not None:
                hash_cap, scan_cap = fc.collect_hash_and_scan(
                    path, scan_plan[0], max_files=max_files, exclude=exclude, walk=walk(),
                    compiled=compiled)
                pending_scan["cap"] = scan_cap
                return hash_cap
        return fc.collect_hashes(path, max_files, exclude, walk=walk())

    # Walk the module's own order so the record reads naturally.
    for check in CHECKS:
        if check in excluded:
            ex = record_skipped(
                case, module=SourceModule.FILES, tool=TOOL_FOR_CHECK[check],
                collection_mode=mode, status=ExecutionStatus.SKIPPED,
                reason="excluded_by_user", target=str(path),
            )
            result.outcomes.append(CheckOutcome(check, ex))
        elif check not in checks:
            continue
        elif check == "hash":
            run("hash", "hashlib", py_version, hash_collect, fc.hashes_to_evidence)
        elif check == "info":
            run("info", "os.stat", py_version,
                lambda: fc.collect_info(path, max_files, exclude, walk=walk()), fc.info_to_evidence)
        elif check == "scan":
            _run_scan(case, path, mode, scan_plan, max_files, exclude, result, run, walk, pending_scan)
    return result


def _scan_plan(path: Path, rules: Path | None) -> tuple[list[Path] | None, str | None, object]:
    """(rule files or None, reason when unavailable, yara ToolInfo)."""
    yara_info = YaraPython().detect()
    if not yara_info.available:
        return None, f"yara-python not installed ({yara_info.reason})", yara_info
    rules_path = rules if rules is not None else default_rules_path()
    rule_files = fc.find_rule_files(rules_path)
    if rules is None:
        # The demo rules are for `atad demo` only: one of them matches ordinary
        # text and gave a false positive on a real laptop. Use --rules to run them.
        rule_files = [f for f in rule_files
                      if "demo" not in f.relative_to(rules_path).parts[:-1]] if rules_path.is_dir() else rule_files
    if not rule_files:
        return None, (f"no YARA rules configured (add rule files to {rules_path} or use --rules; "
                      "the demo rules run only with --rules rules/demo)"
                      if rules is None else f"no YARA rules (.yar/.yara) found at {rules_path}"), yara_info
    return rule_files, None, yara_info


def _run_scan(case, path, mode, plan, max_files, exclude, result, run, walk, pending) -> None:
    rule_files, reason, yara_info = plan
    if rule_files is None:
        ex = record_skipped(
            case, module=SourceModule.FILES, tool="yara-python", collection_mode=mode,
            status=ExecutionStatus.UNAVAILABLE, reason=reason, target=str(path),
        )
        result.outcomes.append(CheckOutcome("scan", ex))
        return

    def collect() -> dict:
        if "cap" in pending:               # already scanned while hashing
            return pending.pop("cap")
        return fc.collect_yara(path, rule_files, max_files=max_files, exclude=exclude, walk=walk())

    run("scan", "yara-python", yara_info.version, collect, fc.yara_to_evidence)
