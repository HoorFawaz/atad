"""Runs the HOST module checks on the machine atad is running on."""

from __future__ import annotations

from dataclasses import dataclass, field

from atad.adapters.catalog import Psutil
from atad.cases.manager import OpenCase
from atad.core.platform import WINDOWS, current_os, local_hostname
from atad.evidence.models import CollectionMode, Evidence, ExecutionStatus, SourceModule
from atad.modules.common import (
    EXCLUDED_BY_USER,
    CheckOutcome,
    run_collector_check,
    skip_check,
)
from atad.modules.host import collector as hc

CHECKS = ["info", "processes", "connections", "users", "startup"]

_COLLECTORS = {
    "info": (hc.collect_info, hc.info_to_evidence),
    "processes": (hc.collect_processes, hc.processes_to_evidence),
    "connections": (hc.collect_connections, hc.connections_to_evidence),
    "users": (hc.collect_users, hc.users_to_evidence),
    "startup": (hc.collect_startup, hc.startup_to_evidence),
}


@dataclass
class HostRunResult:
    case: OpenCase
    host: str
    outcomes: list[CheckOutcome] = field(default_factory=list)

    def outcome(self, check: str) -> CheckOutcome | None:
        return next((o for o in self.outcomes if o.check == check), None)

    @property
    def evidence(self) -> list[Evidence]:
        return [e for o in self.outcomes for e in o.evidence]


def run_host(case: OpenCase, checks: list[str], *, excluded: list[str] | None = None) -> HostRunResult:
    """Collect from THIS machine. Evidence is always local-mode with the real hostname."""
    host = local_hostname()
    mode = CollectionMode.LOCAL
    result = HostRunResult(case=case, host=host)
    excluded = excluded or []
    psutil_info = Psutil().detect()

    for check in CHECKS:
        tool = "winreg/psutil" if check == "startup" else "psutil"
        if check in excluded:
            result.outcomes.append(skip_check(case, module=SourceModule.HOST, check=check, tool=tool,
                                              mode=mode, status=ExecutionStatus.SKIPPED,
                                              reason=EXCLUDED_BY_USER))
            continue
        if check not in checks:
            continue
        reason = None
        if not psutil_info.available:
            reason = "psutil is not installed"
        elif check == "startup" and current_os() != WINDOWS:
            reason = f"startup locations are checked on Windows only (Linux comes in M9)"
        if reason:
            result.outcomes.append(skip_check(case, module=SourceModule.HOST, check=check, tool=tool,
                                              mode=mode, status=ExecutionStatus.UNAVAILABLE,
                                              reason=reason))
            continue
        collect, to_ev = _COLLECTORS[check]
        result.outcomes.append(run_collector_check(
            case, module=SourceModule.HOST, check=check, tool=tool,
            tool_version=psutil_info.version, mode=mode, host=host,
            collect=collect, to_evidence=to_ev,
        ))
    return result
