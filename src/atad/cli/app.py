"""Root CLI application. Sub-command groups are attached here."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from atad import __version__
from atad.cli import cases as cases_cli
from atad.cli import files as files_cli
from atad.cli import log as log_cli
from atad.cli import scope as scope_cli
from atad.cli.context import state
from atad.cli.doctor import doctor

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
