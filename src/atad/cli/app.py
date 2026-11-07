# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Root CLI application. Sub-command groups are attached here."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from atad import __version__
from atad.cli import cases as cases_cli
from atad.cli import correlate as correlate_cli
from atad.cli import files as files_cli
from atad.cli import host as host_cli
from atad.cli import ioc as ioc_cli
from atad.cli import log as log_cli
from atad.cli import net as net_cli
from atad.cli import report as report_cli
from atad.cli import scope as scope_cli
from atad.cli.context import state
from atad.cli.demo import demo
from atad.cli.doctor import doctor
from atad.cli.triage import triage

app = typer.Typer(
    name="atad",
    help="ATAD (عَتاد) — Advanced Toolkit for Attack & Defense.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(cases_cli.app, name="case", help="Create, list and inspect investigation cases.")
app.add_typer(scope_cli.app, name="scope", help="Manage the authorized network scope of a case.")
app.command("doctor")(doctor)
app.add_typer(files_cli.app, name="files")
app.add_typer(log_cli.app, name="log")
app.add_typer(host_cli.app, name="host")
app.add_typer(net_cli.app, name="net")
app.add_typer(ioc_cli.app, name="ioc")
app.command("correlate")(correlate_cli.correlate)
app.command("findings")(correlate_cli.findings)
app.command("timeline")(correlate_cli.timeline)
app.command("report")(report_cli.report)
app.add_typer(report_cli.export_app, name="export")
app.command("triage")(triage)
app.command("demo")(demo)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"atad {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    home: Optional[Path] = typer.Option(
        None, "--home", help="Folder that holds cases (default: $ATAD_HOME or ./cases)."
    ),
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show version and exit."
    ),
) -> None:
    state.home = home
