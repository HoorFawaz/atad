# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad doctor` — check tools, platform and privileges before an investigation."""

from __future__ import annotations

import sys

import typer

from atad.cli.context import handle_errors, state
from atad.core.platform import LINUX, WINDOWS, current_os, is_elevated, local_hostname, os_description
from atad.core.tool_registry import ToolRegistry


def make_registry() -> ToolRegistry:
    """Factory kept separate so tests can swap in fake tools."""
    return ToolRegistry()


@handle_errors
def doctor(
    case: str | None = typer.Option(
        None, "--case", "-c", help="Also record the results in this case."
    ),
) -> None:
    """Check which tools are available and whether atad runs with admin rights."""
    elevated = is_elevated()
    typer.secho("System", bold=True)
    typer.echo(f"  host     : {local_hostname()}")
    typer.echo(f"  os       : {os_description()}")
    py = sys.version.split()[0]
    typer.echo(f"  python   : {py} (built into atad.exe — nothing to install)" if getattr(sys, "frozen", False)
               else f"  python   : {py}")
    admin = {True: "yes", False: "no", None: "unknown"}[elevated]
    typer.echo(f"  admin    : {admin}")
    if elevated is False:
        need = ("Security and Sysmon logs need admin rights." if current_os() == WINDOWS
                else "auth.log, audit.log and other users' files need root.")
        typer.secho(f"  note     : {need}", fg=typer.colors.YELLOW)
    if current_os() not in (WINDOWS, LINUX):
        typer.secho(
            f"  note     : atad supports Windows and Linux; on {current_os()} some checks are not used.",
            fg=typer.colors.YELLOW,
        )

    registry = make_registry()
    infos = registry.detect_all()

    typer.echo()
    typer.secho("Tools", bold=True)
    typer.echo(f"  {'TOOL':<13}{'NEED':<10}{'STATUS':<10}{'VERSION':<12}NOTE")
    missing_required: list[str] = []
    for info in infos:
        adapter = registry.get(info.name)
        need = "required" if info.required else "optional"
        if not adapter.applies_here():
            status, color, note = "n/a", None, info.reason or ""
        elif info.available:
            status, color, note = "ok", typer.colors.GREEN, adapter.purpose
        else:
            status = "missing"
            color = typer.colors.RED if info.required else typer.colors.YELLOW
            note = info.reason or ""
            if info.required:
                missing_required.append(info.name)
        line = f"  {info.name:<13}{need:<10}"
        typer.echo(line, nl=False)
        typer.secho(f"{status:<10}", fg=color, nl=False)
        typer.echo(f"{(info.version or '-'):<12}{note}")

    if case:
        oc = state.manager().open_case(case)
        for info in infos:
            oc.repo.record_tool(
                info.name,
                available=info.available,
                version=info.version,
                path=info.path,
                reason=info.reason,
                detected_at=info.detected_at,
            )
        typer.echo(f"\nRecorded in {oc.case.id}.")

    typer.echo()
    if missing_required:
        typer.secho(
            "Missing required: " + ", ".join(missing_required), fg=typer.colors.RED, bold=True
        )
        raise typer.Exit(code=1)
    typer.secho("Ready. Optional tools that are missing will be reported as unavailable.",
                fg=typer.colors.GREEN)
