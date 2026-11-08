# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad correlate`, `atad findings` and `atad timeline`."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from atad.cli.context import handle_errors, state
from atad.core.exceptions import ValidationError
from atad.correlation.config import load_config
from atad.correlation.engine import correlate as run_correlation
from atad.evidence.models import Finding, Severity

CaseOpt = typer.Option(..., "--case", "-c", help="Case id.")

SEV_COLOR = {
    Severity.CRITICAL: typer.colors.BRIGHT_RED,
    Severity.HIGH: typer.colors.RED,
    Severity.MEDIUM: typer.colors.YELLOW,
    Severity.LOW: typer.colors.CYAN,
    Severity.INFO: None,
}
_SEV_RANK = {s: i for i, s in enumerate(
    [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}


def _line(f: Finding) -> None:
    typer.echo(f"  {f.id}  ", nl=False)
    typer.secho(f"{f.severity.value:<8}", fg=SEV_COLOR.get(f.severity), nl=False)
    typer.echo(f"{f.rule_id or '-':<5} {f.category.value:<11} {f.title}")


@handle_errors
def correlate(
    case: str = CaseOpt,
    config: Optional[Path] = typer.Option(
        None, "--config", help="YAML file with thresholds and disabled_rules."),
    sigma: Optional[Path] = typer.Option(
        None, "--sigma", help="Sigma rule file or folder (default: $ATAD_SIGMA or ./rules/sigma)."),
    no_sigma: bool = typer.Option(False, "--no-sigma", help="Do not run Sigma rules."),
) -> None:
    """Link the evidence in a case into findings and rebuild its timeline."""
    cfg = load_config(config)
    if sigma is not None and not sigma.exists():
        raise ValidationError(f"Sigma rules not found: {sigma}")
    oc = state.manager().open_case(case)
    r = run_correlation(oc.repo, cfg, sigma=None if no_sigma else (sigma or "auto"))

    typer.secho(f"{oc.case.id} — correlation", bold=True)
    typer.echo(f"  evidence: {r.evidence_count}   indicators: {r.ioc_count}   "
               f"previous rule findings replaced: {r.removed}")
    if r.disabled:
        typer.echo(f"  disabled rules: {', '.join(r.disabled)}")
    if r.sigma is not None:
        sg = r.sigma
        typer.echo(f"  Sigma: {len(sg.load.rules)} rule(s) loaded from {sg.load.files} file(s), "
                   f"{len(sg.load.skipped)} skipped, {sg.matched_rules} matched")
        reasons: dict[str, int] = {}
        for _, why in sg.load.skipped:
            key = why.split(":")[0] if why.startswith("unsupported modifier") else why
            reasons[key] = reasons.get(key, 0) + 1
        for why, n in sorted(reasons.items(), key=lambda x: -x[1])[:5]:
            typer.echo(f"    skipped {n}: {why}")
    else:
        typer.echo("  Sigma: no rules (use --sigma PATH, $ATAD_SIGMA or ./rules/sigma)")
    typer.echo()
    if not r.findings:
        typer.secho("  No findings. Nothing in the evidence matched a rule.", fg=typer.colors.GREEN)
    else:
        typer.secho(f"  Findings ({len(r.findings)})", bold=True)
        for f in sorted(r.findings, key=lambda x: (_SEV_RANK[x.severity], x.id)):
            _line(f)
        typer.echo()
        typer.echo("  By rule: " + ", ".join(f"{k} {v}" for k, v in sorted(r.by_rule.items())))
    typer.echo(f"  Timeline: {r.timeline_events} event(s)")
    typer.echo()
    typer.echo(f"  Details: atad findings --case {oc.case.id} --show FND-xxxx"
               f"   ·   atad timeline --case {oc.case.id}")


@handle_errors
def findings(
    case: str = CaseOpt,
    show: Optional[str] = typer.Option(None, "--show", help="Show one finding in full."),
    severity: Optional[Severity] = typer.Option(None, "--min-severity",
                                                help="Only this severity or higher."),
) -> None:
    """List the findings of a case, or show one with its evidence."""
    oc = state.manager().open_case(case)
    items = oc.repo.list_findings()
    if show:
        match = [f for f in items if f.id == show.upper()]
        if not match:
            raise ValidationError(f"no finding {show} in {oc.case.id}")
        f = match[0]
        typer.secho(f"{f.id}  {f.title}", bold=True)
        typer.echo("  severity  : ", nl=False)
        typer.secho(f.severity.value, fg=SEV_COLOR.get(f.severity))
        typer.echo(f"  confidence: {f.confidence.value}")
        typer.echo(f"  category  : {f.category.value}")
        typer.echo(f"  rule      : {f.rule_id or '-'}")
        if f.description:
            typer.echo(f"  note      : {f.description}")
        typer.echo()
        typer.secho("  Why", bold=True)
        typer.echo(f"    {f.rationale}")
        typer.echo()
        typer.secho(f"  Evidence ({len(f.evidence_ids)})", bold=True)
        for ev_id in f.evidence_ids:
            e = oc.repo.get_evidence(ev_id)
            when = e.event_time.strftime("%Y-%m-%d %H:%M:%S") if e.event_time else "no time       "
            typer.echo(f"    {e.id}  {when}  {e.source_module.value:<5} {e.summary}")
        return

    if severity is not None:
        items = [f for f in items if _SEV_RANK[f.severity] <= _SEV_RANK[severity]]
    if not items:
        typer.echo(f"No findings. Run: atad correlate --case {oc.case.id}")
        return
    typer.secho(f"{len(items)} finding(s)", bold=True)
    for f in sorted(items, key=lambda x: (_SEV_RANK[x.severity], x.id)):
        _line(f)


@handle_errors
def timeline(
    case: str = CaseOpt,
    host: Optional[str] = typer.Option(None, "--host", help="Only events from this host."),
    findings_only: bool = typer.Option(False, "--findings-only", help="Only finding markers."),
    limit: int = typer.Option(200, "--limit", help="Maximum events to show."),
) -> None:
    """Show the case timeline (UTC), built by `atad correlate`."""
    oc = state.manager().open_case(case)
    events = oc.repo.list_timeline()
    if host:
        events = [e for e in events if e["host"].lower().split(".")[0] == host.lower().split(".")[0]]
    if findings_only:
        events = [e for e in events if e["finding_id"]]
    if not events:
        typer.echo(f"Timeline is empty. Run: atad correlate --case {oc.case.id}")
        return
    typer.secho(f"{oc.case.id} — timeline, {len(events)} event(s), UTC", bold=True)
    for e in events[:limit]:
        when = e["event_time"][:19].replace("T", " ")
        ref = e["finding_id"] or e["evidence_id"]
        text = f"  {when}  {e['host']:<16} {ref:<11} {e['description']}"
        if e["finding_id"]:
            typer.secho(text, bold=True, fg=typer.colors.RED)
        else:
            typer.echo(text)
    if len(events) > limit:
        typer.echo(f"  ... {len(events) - limit} more (use --limit)")

