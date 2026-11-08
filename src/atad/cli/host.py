# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad host ...` — collect from the machine atad runs on."""

from __future__ import annotations

import typer

from atad.cli.context import get_or_create_case, handle_errors
from atad.cli.output import exit_code, print_checks, print_list, suspicious
from atad.evidence.models import EvidenceKind
from atad.modules.checks import select_checks
from atad.modules.host.runner import CHECKS, HostRunResult, run_host

app = typer.Typer(
    help="Endpoint investigation of THIS machine: system, processes, connections, users, startup.",
    invoke_without_command=True,
)
CaseOpt = typer.Option(None, "--case", "-c", help="Case id (a new case is created if omitted).")


@app.callback()
@handle_errors
def host_all(
    ctx: typer.Context,
    only: str | None = typer.Option(None, "--only", help=f"Only these checks: {','.join(CHECKS)}"),
    skip: str | None = typer.Option(None, "--skip", help="All checks except these."),
    case: str | None = CaseOpt,
) -> None:
    """Run all host checks (or a chosen set). Run atad on the suspect machine."""
    if ctx.invoked_subcommand is not None:
        return
    sel = select_checks(CHECKS, only, skip)
    _execute(sel.selected, sel.excluded, case)


def _single(check: str):
    @handle_errors
    def command(case: str | None = CaseOpt) -> None:
        _execute([check], [], case)
    return command


app.command("info", help="Operating system, hostname, last boot.")(_single("info"))
app.command("processes", help="Running processes (with program hash).")(_single("processes"))
app.command("connections", help="Active connections and listening ports.")(_single("connections"))
app.command("users", help="Logged-in user sessions.")(_single("users"))
app.command("startup", help="Run keys, Startup folders, auto-start services (Windows).")(_single("startup"))


def _execute(checks: list[str], excluded: list[str], case_id: str | None) -> None:
    oc, _ = get_or_create_case(case_id, "host: local collection")
    r = run_host(oc, checks, excluded=excluded)
    _print(r)
    raise typer.Exit(code=exit_code(r.outcomes))


def _print(r: HostRunResult) -> None:
    typer.echo()
    typer.secho(f"{r.case.case.id} — host", bold=True)
    typer.echo(f"  host : {r.host}   mode: local")
    typer.echo()
    print_checks(r.outcomes)

    info = r.outcome("info")
    if info and info.evidence:
        typer.echo()
        typer.echo(f"  {info.evidence[0].summary}")

    procs = r.outcome("processes")
    if procs and procs.capture and procs.capture.get("access_denied"):
        typer.secho(f"\n  note: {procs.capture['access_denied']} process(es) hid details "
                    "(run as admin for full results)", fg=typer.colors.YELLOW)
    print_list("Suspicious processes", suspicious(procs.evidence) if procs else [],
               color=typer.colors.YELLOW)

    conns = r.outcome("connections")
    if conns:
        listening = [e for e in conns.evidence if e.kind is EvidenceKind.OPEN_PORT]
        outbound = [e for e in conns.evidence if e.kind is EvidenceKind.NETWORK_CONNECTION
                    and e.data.get("state") == "ESTABLISHED"]
        print_list("Listening ports", listening, limit=10)
        print_list("Established connections", outbound, limit=10)

    users = r.outcome("users")
    if users:
        print_list("User sessions", users.evidence, limit=10)

    start = r.outcome("startup")
    if start:
        print_list("Suspicious startup items", suspicious(start.evidence), color=typer.colors.YELLOW)
        if start.evidence:
            typer.echo(f"\n  Startup items found: {len(start.evidence)}")

    typer.echo()
    typer.echo(f"  Evidence stored in {r.case.case.id}: {len(r.evidence)} record(s).")
