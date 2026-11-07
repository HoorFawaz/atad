# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad triage`: run the modules of a profile on THIS machine, then correlate,
report and (for DFIR) export — one command for a first look.

| Step              | soc                 | dfir                | full                       |
|-------------------|---------------------|---------------------|----------------------------|
| host              | all checks          | all checks          | all checks                 |
| logs (live)       | last 24 h           | last 7 days         | last 7 days                |
| files (--path)    | hash, info, YARA    | hash, info, YARA    | hash, info, YARA           |
| net               | interfaces; ping + DNS with --target | interfaces; DNS with --target | all, incl. Nmap quick scan with --target |
| IOC (--iocs)      | loaded              | loaded              | loaded                     |
| correlate, report | yes                 | yes                 | yes                        |
| timeline + case zip | no                | yes                 | yes                        |

Why: SOC triage must be fast and quiet, so it never scans. DFIR needs a wider
log window and a preserved, shareable copy of the case. Only `full` runs an
active Nmap scan, and only against an authorized --target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from atad.cases.manager import OpenCase
from atad.correlation.config import CorrelationConfig
from atad.correlation.engine import CorrelationReport, correlate
from atad.evidence.models import Confidence, Execution, ExecutionStatus
from atad.modules.files.runner import CHECKS as FILE_CHECKS
from atad.modules.files.runner import run_files
from atad.modules.host.runner import CHECKS as HOST_CHECKS
from atad.modules.host.runner import run_host
from atad.modules.ioc.loader import load_ioc_file
from atad.modules.logs.runner import CHECKS as LOG_CHECKS
from atad.modules.logs.runner import run_log_live
from atad.modules.net.runner import run_net
from atad.reports.exports import export_case, export_timeline
from atad.reports.writer import WrittenReport, write_reports

MODULES = ["host", "logs", "files", "net"]


@dataclass(frozen=True)
class Profile:
    name: str
    log_hours: int
    net_checks: tuple[str, ...]       # used only with --target (interfaces always runs)
    exports: bool
    scan_profile: str = "quick"


PROFILES = {
    "soc": Profile("soc", 24, ("interfaces", "ping", "dns"), exports=False),
    "dfir": Profile("dfir", 24 * 7, ("interfaces", "dns"), exports=True),
    "full": Profile("full", 24 * 7, ("interfaces", "ping", "scan", "dns"), exports=True),
}


@dataclass
class StepResult:
    name: str
    status: str               # done | limited | partial | failed | skipped
    detail: str = ""
    evidence: int = 0


@dataclass
class TriageResult:
    case: OpenCase
    profile: Profile
    steps: list[StepResult] = field(default_factory=list)
    correlation: CorrelationReport | None = None
    reports: list[WrittenReport] = field(default_factory=list)
    report_data: dict | None = None
    exports: list[Path] = field(default_factory=list)

    @property
    def partial(self) -> bool:
        return any(s.status in ("partial", "failed") for s in self.steps)


def _status(executions: list[Execution]) -> tuple[str, str]:
    """Summarize a module's executions as one step status and a short note.

    done     everything selected ran
    limited  some checks are not available here (tool missing, other OS)
    partial  some checks failed or timed out
    failed   nothing ran because of errors
    skipped  nothing could run here
    """
    ran = [e for e in executions if e.status is ExecutionStatus.SUCCESS]
    bad = [e for e in executions if e.status in (ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT)]
    missing = [e for e in executions if e.status is ExecutionStatus.UNAVAILABLE]
    notes = list(dict.fromkeys(f"{e.tool}: {e.error}" for e in bad + missing if e.error))[:3]
    note = "; ".join(notes)
    if bad:
        return ("partial" if ran else "failed"), note
    if missing:
        return ("limited" if ran else "skipped"), note or "not available here"
    return "done", ""


def run_triage(oc: OpenCase, profile: Profile, modules: list[str], *,
               path: Path | None = None, target: str | None = None,
               iocs: Path | None = None, ioc_confidence: Confidence = Confidence.MEDIUM,
               rules: Path | None = None, hours: int | None = None,
               allow_public: bool = False,
               correlation: CorrelationConfig | None = None) -> TriageResult:
    res = TriageResult(case=oc, profile=profile)

    if iocs is not None:
        load = load_ioc_file(oc, iocs, confidence=ioc_confidence)
        res.steps.append(StepResult("ioc", "done", f"{len(load.iocs)} indicator(s) from {load.source}"
                                    + (f", {len(load.report.rejected)} line(s) rejected"
                                       if load.report.rejected else "")))

    if "host" in modules:
        r = run_host(oc, HOST_CHECKS)
        st, note = _status([o.execution for o in r.outcomes])
        res.steps.append(StepResult("host", st, note, len(r.evidence)))
    else:
        res.steps.append(StepResult("host", "skipped", "left out (--only/--skip)"))

    if "logs" in modules:
        r = run_log_live(oc, LOG_CHECKS, hours=hours or profile.log_hours)
        st, note = _status([o.execution for o in r.outcomes])
        res.steps.append(StepResult("logs", st, note or f"last {hours or profile.log_hours} h",
                                    len(r.evidence)))
    else:
        res.steps.append(StepResult("logs", "skipped", "left out (--only/--skip)"))

    if "files" in modules and path is not None:
        r = run_files(oc, path, FILE_CHECKS, rules=rules)
        st, note = _status([o.execution for o in r.outcomes])
        res.steps.append(StepResult("files", st, note or str(path), len(r.evidence)))
    else:
        why = "left out (--only/--skip)" if "files" not in modules else "no --path given"
        res.steps.append(StepResult("files", "skipped", why))

    if "net" in modules:
        checks = list(profile.net_checks) if target else ["interfaces"]
        r = run_net(oc, checks, target=target, profile=profile.scan_profile,
                    allow_public=allow_public)
        st, note = _status([o.execution for o in r.outcomes])
        if not target and not note:
            note = "interfaces only (no --target)"
        res.steps.append(StepResult("net", st, note, len(r.evidence)))
    else:
        res.steps.append(StepResult("net", "skipped", "left out (--only/--skip)"))

    res.correlation = correlate(oc.repo, correlation)
    res.reports, res.report_data = write_reports(oc)
    if profile.exports:
        written, _ = export_timeline(oc)
        res.exports += [p for p, _ in written]
        zip_path, _, _ = export_case(oc)
        res.exports.append(zip_path)
    return res
