# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad net ...` — network investigation of authorized targets."""

from __future__ import annotations

from typing import Optional

import typer

from atad.cli.context import get_or_create_case, handle_errors
from atad.cli.output import exit_code, print_checks, print_list
from atad.evidence.models import EvidenceKind
from atad.modules.checks import select_checks
from atad.modules.net.collector import NMAP_PROFILES
from atad.modules.net.runner import CHECKS, NetRunResult, run_net

app = typer.Typer(
    help="Network checks: interfaces, ping, Nmap scan, DNS. Only authorized targets.",
    invoke_without_command=True,
)

TargetOpt = typer.Option(None, "--target", "-t", help="IP, CIDR range (max /22) or hostname.")
CaseOpt = typer.Option(
    None, "--case", "-c",
    help="Case id. Without it a new case is created and --target becomes its scope.",
)
ProfileOpt = typer.Option("standard", "--profile", help=f"Scan profile: {', '.join(NMAP_PROFILES)}.")
PortsOpt = typer.Option(None, "--ports", help="Ports to scan, e.g. 22,80,443,8000-8100.")
PublicOpt = typer.Option(False, "--allow-public",
                         help="Allow ping/scan of a public address (only with written authorization).")
MaxHostsOpt = typer.Option(None, "--max-hosts",
                           help="Largest range accepted (default 1024, up to 65536).")


@app.callback()
@handle_errors
def net_all(
    ctx: typer.Context,
    target: Optional[str] = TargetOpt,
    only: Optional[str] = typer.Option(None, "--only", help=f"Only these checks: {','.join(CHECKS)}"),
    skip: Optional[str] = typer.Option(None, "--skip", help="All checks except these."),
    case: Optional[str] = CaseOpt,
    profile: str = ProfileOpt,
    ports: Optional[str] = PortsOpt,
    allow_public: bool = PublicOpt,
    max_hosts: Optional[int] = MaxHostsOpt,
) -> None:
    """Run all network checks (or a chosen set with --only / --skip)."""
    if ctx.invoked_subcommand is not None:
        return
    sel = select_checks(CHECKS, only, skip)
    _execute(sel.selected, sel.excluded, target, case, profile, ports, allow_public, max_hosts)


@app.command("interfaces")
@handle_errors
def interfaces(case: Optional[str] = CaseOpt) -> None:
    """Network interfaces and addresses of this machine."""
    _execute(["interfaces"], [], None, case, "standard", None, False, None)


def _targeted(check: str):
    @handle_errors
    def command(
        target: str = typer.Option(..., "--target", "-t", help="IP, CIDR range or hostname."),
        case: Optional[str] = CaseOpt,
        profile: str = ProfileOpt,
        ports: Optional[str] = PortsOpt,
        allow_public: bool = PublicOpt,
        max_hosts: Optional[int] = MaxHostsOpt,
    ) -> None:
        _execute([check], [], target, case, profile, ports, allow_public, max_hosts)
    return command


app.command("ping", help="Connectivity test.")(_targeted("ping"))
app.command("scan", help="Nmap scan with a safe profile (TCP connect, no scripts).")(_targeted("scan"))
app.command("dns", help="Forward (name -> IP) or reverse (IP -> name) lookup.")(_targeted("dns"))


def _execute(checks, excluded, target, case_id, profile, ports, allow_public, max_hosts) -> None:
    from atad.modules.net.runner import TOUCHES_TARGET
    from atad.utils.validation import validate_target

    if target:
        # Validate BEFORE creating anything, with the same rules run_net uses.
        touches = any(c in TOUCHES_TARGET for c in checks)
        validate_target(target, allow_public=allow_public or not touches,
                        **({"max_addresses": max_hosts} if max_hosts else {}))
    label = f"net: {target}" if target else "net: interfaces"
    oc, _ = get_or_create_case(case_id, label)
    r = run_net(oc, checks, target=target, excluded=excluded, profile=profile,
                ports=ports, allow_public=allow_public, max_hosts=max_hosts)
    if r.scope_added:
        typer.echo(f"  scope: {r.scope_added.value} authorized for {oc.case.id} (recorded)")
    _print(r)
    raise typer.Exit(code=exit_code(r.outcomes))


def _print(r: NetRunResult) -> None:
    typer.echo()
    typer.secho(f"{r.case.case.id} — network", bold=True)
    if r.target:
        typer.echo(f"  target: {r.target.value} ({r.target.kind})")
    typer.echo()
    print_checks(r.outcomes)

    for name in ("interfaces", "ping", "dns"):
        o = r.outcome(name)
        if o and o.evidence:
            typer.echo()
            for e in o.evidence[:10]:
                typer.echo(f"  {e.summary}")

    scan = r.outcome("scan")
    if scan and scan.capture is not None:
        hosts = [e for e in scan.evidence if e.kind is EvidenceKind.HOST_INFO]
        ports = [e for e in scan.evidence if e.kind is EvidenceKind.OPEN_PORT]
        typer.echo()
        typer.secho(f"  Nmap: {len(hosts)} host(s) up", bold=True)
        print_list("Open ports", ports, limit=30)

    typer.echo()
    typer.echo(f"  Evidence stored in {r.case.case.id}: {len(r.evidence)} record(s).")
