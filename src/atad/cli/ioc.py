# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad ioc ...` — load indicator lists and check them against a case."""

from __future__ import annotations

from collections import Counter

import typer

from atad.cli.context import handle_errors, state
from atad.correlation.rules import CaseView, IocIndex
from atad.evidence.models import Confidence, EvidenceKind
from atad.modules.ioc.loader import load_ioc_file
from atad.modules.ioc.parser import SUPPORTED_TYPES
from atad.utils.validation import validate_evidence_path

app = typer.Typer(help="Indicators of compromise: load lists and match them against evidence.",
                  no_args_is_help=True)

CaseOpt = typer.Option(..., "--case", "-c", help="Case id.")


@app.command("load")
@handle_errors
def ioc_load(
    path: str = typer.Option(..., "--path", help="IOC list: .txt (one per line) or .csv."),
    case: str = CaseOpt,
    name: str | None = typer.Option(None, "--name", help="Source name (default: file name)."),
    confidence: Confidence = typer.Option(
        Confidence.MEDIUM, "--confidence",
        help="Confidence for indicators that do not state their own."),
) -> None:
    """Copy an IOC list into the case (hashed) and store its indicators."""
    src = validate_evidence_path(path)
    oc = state.manager().open_case(case)
    load = load_ioc_file(oc, src, name=name, confidence=confidence)
    rec, report, source, iocs, added = (load, load.report, load.source, load.iocs, load.added)

    typer.secho(f"{oc.case.id} — IOC list '{source}'", bold=True)
    typer.echo(f"  copied to {rec.execution.raw_ref} (sha256 {rec.execution.raw_sha256})")
    by_type = Counter(i.type for i in iocs)
    typer.echo(f"  read: {len(iocs)}   new: {added}   already loaded: {len(iocs) - added}")
    for t in SUPPORTED_TYPES:
        if by_type.get(t):
            typer.echo(f"    {t:<8} {by_type[t]}")
    if report.rejected:
        typer.secho(f"  rejected lines: {len(report.rejected)}", fg=typer.colors.YELLOW)
        for line, text, reason in report.rejected[:10]:
            typer.echo(f"    line {line}: {text[:60]!r} — {reason}")
        if len(report.rejected) > 10:
            typer.echo(f"    ... {len(report.rejected) - 10} more")
    typer.echo()
    typer.echo(f"  Next: atad ioc check --case {oc.case.id}   or   atad correlate --case {oc.case.id}")


@app.command("list")
@handle_errors
def ioc_list(
    case: str = CaseOpt,
    limit: int = typer.Option(50, "--limit", help="Maximum indicators to show."),
) -> None:
    """Show the indicators loaded in a case."""
    oc = state.manager().open_case(case)
    iocs = oc.repo.list_iocs()
    if not iocs:
        typer.echo("No indicators loaded. Use: atad ioc load --case ID --path list.txt")
        return
    typer.secho(f"{len(iocs)} indicator(s)", bold=True)
    for i in iocs[:limit]:
        desc = f"  — {i.description}" if i.description else ""
        typer.echo(f"  {i.type:<7} {i.value:<45} {i.confidence.value:<7} {i.source}{desc}")
    if len(iocs) > limit:
        typer.echo(f"  ... {len(iocs) - limit} more (use --limit)")


@app.command("check")
@handle_errors
def ioc_check(case: str = CaseOpt) -> None:
    """Show which loaded indicators appear in the case evidence (read-only)."""
    oc = state.manager().open_case(case)
    view = CaseView(oc.case.id, oc.repo.list_evidence(), oc.repo.list_iocs())
    if not view.iocs:
        typer.echo("No indicators loaded. Use: atad ioc load --case ID --path list.txt")
        return
    index = IocIndex(view.iocs)
    hits: dict[tuple[str, str], list[str]] = {}
    for e in view.evidence:
        if e.kind is EvidenceKind.INTERFACE:
            continue
        for o in e.observables:
            for i in index.match(o):
                hits.setdefault((i.type, i.value), []).append(e.id)
    if not hits:
        typer.secho(f"None of the {len(view.iocs)} indicator(s) appear in "
                    f"{len(view.evidence)} evidence record(s).", fg=typer.colors.GREEN)
        return
    typer.secho(f"{len(hits)} indicator(s) seen in the evidence", bold=True, fg=typer.colors.RED)
    for (kind, value), ids in sorted(hits.items()):
        ids = list(dict.fromkeys(ids))
        typer.echo(f"  {kind:<7} {value}")
        for ev_id in ids[:5]:
            typer.echo(f"      {ev_id}  {view.by_id[ev_id].summary}")
        if len(ids) > 5:
            typer.echo(f"      ... {len(ids) - 5} more")
    typer.echo()
    typer.echo(f"  To record these as findings: atad correlate --case {oc.case.id}")
