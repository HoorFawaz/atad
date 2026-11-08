# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad triage` — every module of a profile, then correlate, report and export."""

from __future__ import annotations

from pathlib import Path

import typer

from atad.cli.context import handle_errors, state
from atad.cli.correlate import SEV_COLOR
from atad.cli.report import check_tlp
from atad.core.exceptions import ValidationError
from atad.core.platform import local_hostname
from atad.correlation.config import load_config
from atad.evidence.models import Confidence
from atad.evidence.models import Profile as CaseProfile
from atad.modules.checks import select_checks
from atad.modules.net.runner import TOUCHES_TARGET
from atad.reports.builder import report_problems
from atad.triage import MODULES, PROFILES, run_triage
from atad.utils.validation import validate_evidence_path, validate_target

STEP_COLOR = {"done": typer.colors.GREEN, "limited": typer.colors.YELLOW,
              "partial": typer.colors.YELLOW,
              "failed": typer.colors.RED, "skipped": None}


@handle_errors
def triage(
    profile: str | None = typer.Option(
        None, "--profile", "-p", help="soc (fast, no scanning), dfir (deeper + exports) or full."),
    case: str | None = typer.Option(None, "--case", "-c",
                                       help="Add to this case (default: create a new one)."),
    only: str | None = typer.Option(None, "--only", help=f"Only these modules: {','.join(MODULES)}"),
    skip: str | None = typer.Option(None, "--skip", help="All modules except these."),
    path: str | None = typer.Option(None, "--path", help="Folder or file for the files module."),
    target: str | None = typer.Option(None, "--target", "-t",
                                         help="Authorized network target for the net module."),
    iocs: str | None = typer.Option(None, "--iocs", help="IOC list (.txt / .csv) to load first."),
    ioc_confidence: Confidence = typer.Option(Confidence.MEDIUM, "--ioc-confidence",
                                              help="Confidence for indicators without their own."),
    rules: Path | None = typer.Option(None, "--rules", help="YARA rules (default: $ATAD_RULES or ./rules)."),
    hours: int | None = typer.Option(None, "--hours", min=1, max=24 * 90,
                                        help="Log window (default: 24 for soc, 168 for dfir/full)."),
    allow_public: bool = typer.Option(False, "--allow-public",
                                      help="Allow contacting a public --target (written authorization only)."),
    config: Path | None = typer.Option(None, "--config", help="Correlation thresholds (YAML)."),
    tlp: str = typer.Option("amber", "--tlp", help="Report classification (TLP 2.0): clear, green, amber, amber+strict, red."),
) -> None:
    """First look at THIS machine: run the profile's modules, correlate, report."""
    # Everything is validated before anything is created or run.
    sel = select_checks(MODULES, only, skip)
    tlp = check_tlp(tlp)
    src = validate_evidence_path(path) if path else None
    ioc_path = validate_evidence_path(iocs) if iocs else None
    cfg = load_config(config)
    if profile is not None and profile not in PROFILES:
        raise ValidationError(f"--profile must be one of: {', '.join(PROFILES)}")
    mgr = state.manager()
    oc = mgr.open_case(case) if case else None
    prof = PROFILES[profile or (oc.case.profile.value if oc else "soc")]
    if target and "net" in sel.selected:
        touches = any(c in TOUCHES_TARGET for c in prof.net_checks)
        validate_target(target, allow_public=allow_public or not touches)
    elif target:
        raise ValidationError("--target is only used by the net module, which is left out")
    if path and "files" not in sel.selected:
        raise ValidationError("--path is only used by the files module, which is left out")

    if oc is None:
        oc = mgr.create_case(f"triage ({prof.name}) on {local_hostname()}", CaseProfile(prof.name))
        typer.secho(f"Created {oc.case.id} ({oc.path})", fg=typer.colors.GREEN)

    typer.secho(f"{oc.case.id} — triage, profile {prof.name}", bold=True)
    r = run_triage(oc, prof, sel.selected, path=src, target=target, iocs=ioc_path,
                   ioc_confidence=ioc_confidence, rules=rules, hours=hours,
                   allow_public=allow_public, correlation=cfg, tlp=tlp)

    typer.echo()
    typer.secho("  Steps", bold=True)
    for s in r.steps:
        typer.echo(f"    {s.name:<7}", nl=False)
        typer.secho(f"{s.status:<9}", fg=STEP_COLOR.get(s.status), nl=False)
        typer.echo((f"{s.evidence} evidence  " if s.evidence else "") + s.detail)

    c = r.correlation
    typer.echo()
    typer.secho(f"  Findings ({len(c.findings)})", bold=True)
    rank = ["critical", "high", "medium", "low", "info"]
    for f in sorted(c.findings, key=lambda x: (rank.index(x.severity.value), x.id))[:12]:
        typer.echo(f"    {f.id}  ", nl=False)
        typer.secho(f"{f.severity.value:<8}", fg=SEV_COLOR.get(f.severity), nl=False)
        typer.echo(f"{f.rule_id or '-':<5} {f.title}")
    if len(c.findings) > 12:
        typer.echo(f"    ... {len(c.findings) - 12} more: atad findings --case {oc.case.id}")
    if not c.findings:
        typer.echo("    none — see the report's Coverage section for what was checked")

    typer.echo()
    for w in r.reports:
        typer.echo(f"  report {w.format:<5} {w.path}")
    for p in r.exports:
        typer.echo(f"  export       {p}")
    problems = report_problems(r.report_data)
    for p in problems:
        typer.secho(f"  attention: {p}", fg=typer.colors.YELLOW)

    integ = r.report_data["summary"]["integrity"]
    if integ["changed"] or integ["missing"] or integ["unsafe-path"]:
        raise typer.Exit(code=4)
    if r.partial:
        raise typer.Exit(code=3)
