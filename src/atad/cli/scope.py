# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad scope ...` commands — the authorized network targets of a case."""

from __future__ import annotations

import typer

from atad.cli.context import handle_errors, state

app = typer.Typer(no_args_is_help=True)


@app.command("add")
@handle_errors
def add(
    case: str = typer.Option(..., "--case", "-c", help="Case id, e.g. CASE-001."),
    target: str = typer.Option(..., "--target", "-t", help="IP, CIDR range or hostname."),
    note: str = typer.Option("", "--note", help="Why this target is authorized."),
    allow_public: bool = typer.Option(
        False, "--allow-public", help="Allow a public address (only with written authorization)."
    ),
    max_hosts: int | None = typer.Option(
        None, "--max-hosts", help="Largest range accepted (default 1024, up to 65536)."
    ),
) -> None:
    """Authorize a network target for a case."""
    t, added = state.manager().add_scope(case, target, allow_public=allow_public, note=note,
                                         max_addresses=max_hosts)
    if added:
        typer.secho(f"Added to scope: {t.value} ({t.kind})", fg=typer.colors.GREEN)
        if t.is_public:
            typer.secho("  warning: public address — make sure you are authorized.",
                        fg=typer.colors.YELLOW)
    else:
        typer.echo(f"Already in scope: {t.value}")


@app.command("list")
@handle_errors
def list_scope(case: str = typer.Option(..., "--case", "-c", help="Case id.")) -> None:
    """Show the authorized targets of a case."""
    oc = state.manager().open_case(case)
    targets = oc.repo.list_targets()
    if not targets:
        typer.echo("No targets in scope.")
        return
    for t in targets:
        flag = "  PUBLIC" if t.is_public else ""
        note = f"  — {t.note}" if t.note else ""
        typer.echo(f"{t.value:<20}{t.kind:<10}{flag}{note}")
