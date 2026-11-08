# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad report` and `atad export ...`."""

from __future__ import annotations

import typer

from atad.cli.context import handle_errors, state
from atad.core.exceptions import ValidationError
from atad.reports.builder import DEFAULT_TLP, TLP_LEVELS, report_problems
from atad.reports.exports import TIMELINE_FORMATS, export_case, export_timeline
from atad.reports.writer import FORMATS, write_reports

CaseOpt = typer.Option(..., "--case", "-c", help="Case id.")


def _formats(value: str, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if value == "all":
        return allowed
    chosen = tuple(dict.fromkeys(v.strip().lower() for v in value.split(",") if v.strip()))
    bad = [v for v in chosen if v not in allowed]
    if bad or not chosen:
        raise ValidationError(f"--format must be {', '.join(allowed)} or all")
    return chosen


def check_tlp(value: str) -> str:
    v = value.strip().lower().removeprefix("tlp:")
    if v not in TLP_LEVELS:
        raise ValidationError(f"--tlp must be one of: {', '.join(TLP_LEVELS)}")
    return v


@handle_errors
def report(
    case: str = CaseOpt,
    fmt: str = typer.Option("all", "--format", "-f", help="html, json or all."),
    tlp: str = typer.Option(DEFAULT_TLP, "--tlp",
                            help=f"Classification (TLP 2.0): {', '.join(TLP_LEVELS)}."),
) -> None:
    """Write the case report (HTML for people, JSON for tools) into reports/."""
    tlp = check_tlp(tlp)
    oc = state.manager().open_case(case)
    written, data = write_reports(oc, _formats(fmt, FORMATS), tlp=tlp)
    s = data["summary"]
    typer.secho(f"{oc.case.id} — report", bold=True)
    typer.echo(f"  findings: {s['findings_total']}   evidence: {s['evidence_total']}   "
               f"raw files verified: {s['integrity']['verified']}/{s['integrity']['checked']}")
    if s["findings_total"] == 0:
        typer.echo(f"  (no findings — run `atad correlate --case {oc.case.id}` first if you have not)")
    for p in report_problems(data):
        typer.secho(f"  attention: {p}", fg=typer.colors.YELLOW)
    typer.echo()
    for w in written:
        typer.echo(f"  {w.format:<5} {w.path}")
        typer.echo(f"        sha256 {w.sha256}")
    integ = s["integrity"]
    if integ["changed"] or integ["missing"] or integ["unsafe-path"]:
        raise typer.Exit(code=4)


export_app = typer.Typer(help="Export the timeline or the whole case for other tools.",
                         no_args_is_help=True)


@export_app.command("timeline")
@handle_errors
def export_timeline_cmd(
    case: str = CaseOpt,
    fmt: str = typer.Option("all", "--format", "-f", help="csv, jsonl or all."),
) -> None:
    """Timeline as CSV / JSONL (Timesketch, Timeline Explorer, Elastic)."""
    oc = state.manager().open_case(case)
    written, n = export_timeline(oc, _formats(fmt, TIMELINE_FORMATS))
    typer.secho(f"{oc.case.id} — timeline export, {n} row(s), UTC", bold=True)
    for path, digest in written:
        typer.echo(f"  {path}")
        typer.echo(f"    sha256 {digest}")


@export_app.command("case")
@handle_errors
def export_case_cmd(case: str = CaseOpt) -> None:
    """The whole case folder as one zip, with SHA256SUMS.txt inside."""
    oc = state.manager().open_case(case)
    path, digest, n = export_case(oc)
    typer.secho(f"{oc.case.id} — case export, {n} file(s)", bold=True)
    typer.echo(f"  {path}")
    typer.echo(f"    sha256 {digest}")
    typer.echo("  Give the receiver this hash so they can check the zip arrived unchanged.")
