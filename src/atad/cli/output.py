# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Shared console output for module runs."""

from __future__ import annotations

from collections.abc import Iterable

import typer

from atad.evidence.models import Evidence, ExecutionStatus
from atad.modules.common import CheckOutcome

COLOR = {
    ExecutionStatus.SUCCESS: typer.colors.GREEN,
    ExecutionStatus.FAILED: typer.colors.RED,
    ExecutionStatus.TIMEOUT: typer.colors.RED,
    ExecutionStatus.UNAVAILABLE: typer.colors.YELLOW,
}


def print_checks(outcomes: Iterable[CheckOutcome]) -> None:
    typer.secho("  Checks", bold=True)
    for o in outcomes:
        ex = o.execution
        label = "skipped (your choice)" if o.excluded_by_user else ex.status.value
        typer.echo(f"    {o.check:<12}", nl=False)
        typer.secho(f"{label:<22}", fg=COLOR.get(ex.status), nl=False)
        if ex.status is ExecutionStatus.SUCCESS:
            note = f"{len(o.evidence)} evidence"
            if ex.error:
                note += f" — {ex.error}"
            typer.echo(note)
        else:
            typer.echo("" if o.excluded_by_user else (ex.error or ""))


def print_list(title: str, items: list[Evidence], limit: int = 15,
               color: str | None = None) -> None:
    if not items:
        return
    typer.echo()
    typer.secho(f"  {title} ({len(items)})", bold=True, fg=color)
    for e in items[:limit]:
        typer.echo(f"    {e.id}  {e.summary}")
    if len(items) > limit:
        typer.echo(f"    ... {len(items) - limit} more in the case")


def suspicious(items: list[Evidence]) -> list[Evidence]:
    return [e for e in items if e.data.get("suspicious_reasons")]


def exit_code(outcomes: Iterable[CheckOutcome]) -> int:
    return 3 if any(o.execution.status in (ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT)
                    for o in outcomes) else 0
