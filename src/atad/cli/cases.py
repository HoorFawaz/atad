# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad case ...` commands."""

from __future__ import annotations

import typer

from atad.cli.context import handle_errors, state
from atad.evidence.models import Profile

app = typer.Typer(no_args_is_help=True)


@app.command("new")
@handle_errors
def new_case(
    name: str = typer.Option(..., "--name", "-n", help="Short case name."),
    profile: Profile = typer.Option(Profile.SOC, "--profile", "-p", help="Investigation profile."),
    description: str = typer.Option("", "--description", "-d", help="Optional description."),
    simulated: bool = typer.Option(
        False, "--simulated", help="Mark the case as using synthetic/demo data."
    ),
) -> None:
    """Create a new investigation case."""
    oc = state.manager().create_case(
        name, profile, description=description, simulated=simulated
    )
    typer.secho(f"Created {oc.case.id}", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"  name     : {oc.case.name}")
    typer.echo(f"  profile  : {oc.case.profile.value}")
    if oc.case.simulated:
        typer.echo("  data     : SIMULATED")
    typer.echo(f"  folder   : {oc.path}")


@app.command("list")
@handle_errors
def list_cases() -> None:
    """List all cases."""
    cases = state.manager().list_cases()
    if not cases:
        typer.echo("No cases yet. Create one with: atad case new --name \"...\"")
        return
    typer.echo(f"{'ID':<12}{'PROFILE':<9}{'CREATED (UTC)':<18}{'SIM':<5}NAME")
    for oc in cases:
        c = oc.case
        created = c.created_at.strftime("%Y-%m-%d %H:%M")
        sim = "yes" if c.simulated else ""
        typer.echo(f"{c.id:<12}{c.profile.value:<9}{created:<18}{sim:<5}{c.name}")


@app.command("show")
@handle_errors
def show_case(case_id: str = typer.Argument(..., help="Case id, e.g. CASE-001.")) -> None:
    """Show details of one case."""
    oc = state.manager().open_case(case_id)
    c = oc.case
    typer.secho(c.id, bold=True)
    typer.echo(f"  name        : {c.name}")
    if c.description:
        typer.echo(f"  description : {c.description}")
    typer.echo(f"  profile     : {c.profile.value}")
    typer.echo(f"  simulated   : {'yes' if c.simulated else 'no'}")
    typer.echo(f"  created     : {c.created_at.isoformat()}")
    typer.echo(f"  atad        : {c.atad_version}")
    typer.echo(f"  folder      : {oc.path}")

    targets = oc.repo.list_targets()
    typer.echo("  scope       : " + (", ".join(t.value for t in targets) if targets else "(none)"))

    counts = oc.repo.counts()
    typer.echo(
        "  records     : "
        + ", ".join(f"{k}={v}" for k, v in counts.items() if k != "targets")
    )
