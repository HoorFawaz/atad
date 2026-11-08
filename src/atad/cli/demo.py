# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad demo` — build the SIMULATED demo case, correlate, report, and score the rules."""

from __future__ import annotations

import json
import os
import stat

import typer

from atad.cli.context import handle_errors, state
from atad.correlation.engine import correlate
from atad.demo.builder import build_demo
from atad.demo.evaluate import evaluate
from atad.evidence.models import utc_now
from atad.reports.builder import file_stamp
from atad.reports.exports import export_timeline
from atad.reports.writer import write_reports


@handle_errors
def demo() -> None:
    """Create a case from the built-in SIMULATED scenario and measure the rules on it."""
    b = build_demo(state.manager())
    oc = b.case
    typer.secho(f"Created {oc.case.id} — {oc.case.name}", fg=typer.colors.GREEN, bold=True)
    typer.secho("  All data in this case is SIMULATED.", fg=typer.colors.YELLOW)
    typer.echo()
    typer.secho("  Story", bold=True)
    for line in b.scenario["story"]:
        typer.echo(f"    {line}")
    typer.echo()
    typer.secho("  Loaded through the real parsers", bold=True)
    for step, n in b.steps:
        typer.echo(f"    {step:<14} {n} record(s)")
    if not b.yara_available:
        typer.secho("    YARA is not installed: YARA-based findings cannot be produced "
                    "(pip install \"atad[yara]\").", fg=typer.colors.YELLOW)

    result = correlate(oc.repo, sigma=None)   # the labels cover ATAD's own rules
    m = evaluate(result.findings, b.scenario["expected"],
                 available={"yara"} if b.yara_available else set())

    typer.echo()
    typer.secho(f"  Findings ({len(result.findings)}) compared with the labels", bold=True)
    typer.echo(f"    {'rule':<6}{'found':>6}{'wrong':>7}{'missed':>8}")
    for rule, c in m.per_rule().items():
        typer.echo(f"    {rule:<6}{c['tp']:>6}{c['fp']:>7}{c['fn']:>8}")
    typer.echo()
    typer.echo(f"    precision {m.precision:.0%}  (findings that were right)")
    typer.echo(f"    recall    {m.recall:.0%}  (expected findings that were found)")
    typer.echo(f"    decoys    {len(b.scenario['decoys'])} look-alike benign activities mixed in")
    for e in m.fn:
        typer.secho(f"    missed: {e['rule']} {e['title']}", fg=typer.colors.RED)
    known = {(k["rule"], k["title"]): k["why"] for k in b.scenario.get("known_false_positives", [])}
    for f in m.fp:
        why = known.get((f.rule_id, f.title))
        if why:
            typer.secho(f"    known false positive: {f.id} {f.rule_id} {f.title}", fg=typer.colors.YELLOW)
            typer.echo(f"      {why}")
        else:
            typer.secho(f"    not expected: {f.id} {f.rule_id} {f.title}", fg=typer.colors.RED)
    for e in m.not_testable:
        typer.secho(f"    not testable here: {e['title']} (needs {e['needs']})",
                    fg=typer.colors.YELLOW)

    written, _ = write_reports(oc, tlp="clear")   # simulated data: free to share
    exports, _ = export_timeline(oc)
    metrics_path = oc.path / "exports" / f"{oc.case.id}_demo_metrics_{file_stamp(utc_now())}.json"
    metrics_path.write_text(json.dumps({"case": oc.case.id, "simulated": True,
                                        "decoys": b.scenario["decoys"], **m.as_dict()},
                                       indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(metrics_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

    typer.echo()
    for w in written:
        typer.echo(f"  report {w.format:<5} {w.path}")
    for p, _ in exports:
        typer.echo(f"  export       {p}")
    typer.echo(f"  metrics      {metrics_path}")
    typer.echo()
    typer.echo(f"  Next: atad findings --case {oc.case.id}   ·   atad timeline --case {oc.case.id}")
