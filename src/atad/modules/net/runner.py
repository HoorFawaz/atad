"""Runs the NET module checks.

Every check that touches another machine (ping, scan, dns) is limited to the
case's authorized scope. Interfaces only read this machine's own settings.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from atad.adapters.base import ParseContext
from atad.adapters.catalog import Nmap, Ping, Psutil
from atad.cases.manager import OpenCase
from atad.core.exceptions import ScopeError
from atad.core.execution import execute_and_record
from atad.core.platform import current_os, local_hostname
from atad.evidence.models import CollectionMode, Evidence, ExecutionStatus, SourceModule, Target
from atad.modules.common import (
    EXCLUDED_BY_USER,
    CheckOutcome,
    run_collector_check,
    skip_check,
)
from atad.modules.net import collector as nc
from atad.utils.validation import ValidatedTarget, validate_target

CHECKS = ["interfaces", "ping", "scan", "dns"]
TOOL_FOR_CHECK = {"interfaces": "psutil", "ping": "ping", "scan": "nmap", "dns": "system resolver"}

SCAN_TIMEOUT_HOST = 300
SCAN_TIMEOUT_RANGE = 900


@dataclass
class NetRunResult:
    case: OpenCase
    target: ValidatedTarget | None
    outcomes: list[CheckOutcome] = field(default_factory=list)

    def outcome(self, check: str) -> CheckOutcome | None:
        return next((o for o in self.outcomes if o.check == check), None)

    @property
    def evidence(self) -> list[Evidence]:
        return [e for o in self.outcomes for e in o.evidence]


# --------------------------------------------------------------------- scope


def _net(value: str):
    return ipaddress.ip_network(value, strict=False)


def _covered(ip_or_net: str, scope: list[Target]) -> Target | None:
    net = _net(ip_or_net)
    for t in scope:
        if t.kind in ("ip", "cidr"):
            s = _net(t.value)
            if net.version == s.version and net.subnet_of(s):
                return t
    return None


def scan_targets(vt: ValidatedTarget, scope: list[Target]) -> list[str]:
    """Return the concrete addresses to probe, or raise ScopeError.

    * IP / CIDR: must sit inside an authorized IP/CIDR entry.
    * Hostname: must be authorized by name, and every address it resolves to
      must be internal or itself authorized — so a name can't quietly point
      atad at an outside system.
    """
    if vt.kind in ("ip", "cidr"):
        if not _covered(vt.value, scope):
            raise ScopeError(f"{vt.value} is not in this case's authorized scope "
                             f"(add it with: atad scope add --case ... --target {vt.value})")
        return [vt.value]

    names = {t.value for t in scope if t.kind == "hostname"}
    if vt.value not in names:
        raise ScopeError(f"{vt.value} is not in this case's authorized scope")
    ips = nc.resolve_name(vt.value)
    if not ips:
        raise ScopeError(f"{vt.value} did not resolve to any address")
    for ip in ips:
        addr = ipaddress.ip_address(ip.split("%")[0])
        internal = addr.is_private or addr.is_loopback or addr.is_link_local
        if not internal and not _covered(str(addr), scope):
            raise ScopeError(f"{vt.value} resolves to public address {addr}, which is not authorized")
    return ips


# -------------------------------------------------------------------- runner


def run_net(case: OpenCase, checks: list[str], *, target: str | None = None,
            excluded: list[str] | None = None, profile: str = "standard",
            ports: str | None = None, allow_public: bool = False) -> NetRunResult:
    excluded = excluded or []
    vt = validate_target(target, allow_public=allow_public) if target else None
    result = NetRunResult(case=case, target=vt)
    scope = case.repo.list_targets()
    needs_target = [c for c in checks if c != "interfaces"]
    addresses: list[str] = []
    if vt and needs_target:
        addresses = scan_targets(vt, scope)  # raises before anything runs

    for check in CHECKS:
        mode = CollectionMode.LOCAL if check == "interfaces" else CollectionMode.NETWORK
        tool = TOOL_FOR_CHECK[check]
        if check in excluded:
            result.outcomes.append(skip_check(case, module=SourceModule.NET, check=check, tool=tool,
                                              mode=mode, status=ExecutionStatus.SKIPPED,
                                              reason=EXCLUDED_BY_USER, target=target))
            continue
        if check not in checks:
            continue
        if check != "interfaces" and vt is None:
            result.outcomes.append(skip_check(case, module=SourceModule.NET, check=check, tool=tool,
                                              mode=mode, status=ExecutionStatus.SKIPPED,
                                              reason="no --target given"))
            continue
        if check in ("ping", "dns") and vt.kind == "cidr":
            result.outcomes.append(skip_check(case, module=SourceModule.NET, check=check, tool=tool,
                                              mode=mode, status=ExecutionStatus.SKIPPED,
                                              reason=f"{check} needs a single host, not a range",
                                              target=vt.value))
            continue

        if check == "interfaces":
            info = Psutil().detect()
            result.outcomes.append(run_collector_check(
                case, module=SourceModule.NET, check=check, tool="psutil",
                tool_version=info.version, mode=mode, host=local_hostname(),
                collect=nc.collect_interfaces, to_evidence=nc.interfaces_to_evidence))
        elif check == "dns":
            result.outcomes.append(run_collector_check(
                case, module=SourceModule.NET, check=check, tool="system resolver",
                tool_version=None, mode=mode, host=vt.value, target=vt.value,
                collect=lambda: nc.collect_dns(vt.value), to_evidence=nc.dns_to_evidence))
        elif check == "ping":
            result.outcomes.append(_ping(case, vt.value))
        elif check == "scan":
            result.outcomes.append(_scan(case, vt, addresses, profile, ports))
    return result


def _ctx(case: OpenCase, ex, host: str, version: str | None) -> ParseContext:
    return ParseContext(case_id=case.case.id, host=host, collection_mode=CollectionMode.NETWORK,
                        execution_id=ex.id, raw_ref=ex.raw_ref, raw_sha256=ex.raw_sha256,
                        tool_version=version, simulated=case.case.simulated)


def _ping(case: OpenCase, target: str) -> CheckOutcome:
    info = Ping().detect()
    if not info.available:
        return skip_check(case, module=SourceModule.NET, check="ping", tool="ping",
                          mode=CollectionMode.NETWORK, status=ExecutionStatus.UNAVAILABLE,
                          reason=info.reason or "ping not found", target=target)
    rec = execute_and_record(
        case, module=SourceModule.NET, tool="ping", tool_version=info.version,
        args=nc.build_ping_args(info.path, target, current_os()),
        collection_mode=CollectionMode.NETWORK, target=target, timeout=30,
    )
    outcome = CheckOutcome("ping", rec.execution)
    r = rec.result
    if r is not None and rec.execution.status in (ExecutionStatus.SUCCESS, ExecutionStatus.FAILED):
        # ping exits non-zero when nothing replies: that is a result, not a tool failure.
        parsed = nc.parse_ping(r.stdout, r.exit_code, target)
        if rec.execution.status is ExecutionStatus.FAILED and r.exit_code == 1 and not parsed["reachable"]:
            ex = rec.execution.model_copy(update={"status": ExecutionStatus.SUCCESS,
                                                  "error": "no reply (host down or blocking ping)"})
            case.repo.finish_execution(ex)
            outcome.execution = ex
        outcome.capture = parsed
        outcome.evidence = case.repo.add_evidence_many(
            nc.ping_to_evidence(parsed, _ctx(case, outcome.execution, target, info.version)))
    return outcome


def _scan(case: OpenCase, vt: ValidatedTarget, addresses: list[str],
          profile: str, ports: str | None) -> CheckOutcome:
    info = Nmap().detect()
    if not info.available:
        return skip_check(case, module=SourceModule.NET, check="scan", tool="nmap",
                          mode=CollectionMode.NETWORK, status=ExecutionStatus.UNAVAILABLE,
                          reason=f"Nmap is not installed ({info.reason})", target=vt.value)
    single = vt.kind != "cidr"
    rec = execute_and_record(
        case, module=SourceModule.NET, tool="nmap", tool_version=info.version,
        args=nc.build_nmap_args(info.path, addresses, profile, ports, single_host=single),
        collection_mode=CollectionMode.NETWORK, target=vt.value,
        timeout=SCAN_TIMEOUT_HOST if single else SCAN_TIMEOUT_RANGE,
    )
    outcome = CheckOutcome("scan", rec.execution)
    if rec.execution.status is ExecutionStatus.SUCCESS and rec.result is not None:
        try:
            parsed = nc.parse_nmap_xml(rec.result.stdout)
        except Exception as exc:  # bad or partial XML
            ex = rec.execution.model_copy(update={"status": ExecutionStatus.FAILED,
                                                  "error": f"could not read Nmap output: {exc}"})
            case.repo.finish_execution(ex)
            outcome.execution = ex
            return outcome
        outcome.capture = parsed
        outcome.evidence = case.repo.add_evidence_many(
            nc.nmap_to_evidence(parsed, _ctx(case, rec.execution, vt.value, info.version)))
    return outcome

