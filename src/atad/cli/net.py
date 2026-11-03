"""`atad net ...` — network investigation of authorized targets."""

from __future__ import annotations

from typing import Optional

import typer

from atad.cli.context import get_or_create_case, handle_errors, state
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
                         help="Allow a public address (only with written authorization).")


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
) -> None:
    """Run all network checks (or a chosen set with --only / --skip)."""
    if ctx.invoked_subcommand is not None:
        return
    sel = select_checks(CHECKS, only, skip)
    _execute(sel.selected, sel.excluded, target, case, profile, ports, allow_public)


@app.command("interfaces")
@handle_errors
def interfaces(case: Optional[str] = CaseOpt) -> None:
    """Network interfaces and addresses of this machine."""
    _execute(["interfaces"], [], None, case, "standard", None, False)


def _targeted(check: str):
    @handle_errors
    def command(
        target: str = typer.Option(..., "--target", "-t", help="IP, CIDR range or hostname."),
        case: Optional[str] = CaseOpt,
        profile: str = ProfileOpt,
        ports: Optional[str] = PortsOpt,
        allow_public: bool = PublicOpt,
    ) -> None:
        _execute([check], [], target, case, profile, ports, allow_public)
    return command


app.command("ping", help="Connectivity test.")(_targeted("ping"))
app.command("scan", help="Nmap scan with a safe profile (TCP connect, no scripts).")(_targeted("scan"))
app.command("dns", help="Forward (name -> IP) or reverse (IP -> name) lookup.")(_targeted("dns"))


def _execute(checks, excluded, target, case_id, profile, ports, allow_public) -> None:
    label = f"net: {target}" if target else "net: interfaces"
    if case_id is None and target:
        # Validate the target BEFORE creating anything.
        from atad.utils.validation import validate_target
        validate_target(target, allow_public=allow_public)
    oc, created = get_or_create_case(case_id, label)
    if created and target:
        t, _ = state.manager().add_scope(oc.case.id, target, allow_public=allow_public,
                                         note="added automatically by atad net")
        typer.echo(f"  scope: {t.value} authorized for {oc.case.id}")
    r = run_net(oc, checks, target=target, excluded=excluded, profile=profile,
                ports=ports, allow_public=allow_public)
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
