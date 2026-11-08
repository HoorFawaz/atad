# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad files ...` — file investigation (hash, metadata, YARA)."""

from __future__ import annotations

from pathlib import Path

import typer

from atad.cli.context import get_or_create_case, handle_errors
from atad.evidence.models import ExecutionStatus
from atad.modules.checks import select_checks
from atad.modules.files.runner import CHECKS, FilesRunResult, run_files
from atad.utils.validation import validate_evidence_path

app = typer.Typer(
    help="File investigation: hashes, metadata and YARA scanning (read-only).",
    invoke_without_command=True,
)

# Shared option definitions
PathOpt = typer.Option(None, "--path", help="File or folder to investigate.")
CaseOpt = typer.Option(None, "--case", "-c", help="Case id (a new case is created if omitted).")
HostOpt = typer.Option(
    None, "--source-host",
    help="Files were copied from this machine (import mode). Omit when atad runs on the machine itself.",
)
RulesOpt = typer.Option(None, "--rules", help="YARA rule file or folder (default: $ATAD_RULES or ./rules).")
MaxFilesOpt = typer.Option(10_000, "--max-files", min=1, max=10_000_000,
                           help="Stop after this many files (default 10000).")

_STATUS_COLOR = {
    ExecutionStatus.SUCCESS: typer.colors.GREEN,
    ExecutionStatus.FAILED: typer.colors.RED,
    ExecutionStatus.TIMEOUT: typer.colors.RED,
    ExecutionStatus.UNAVAILABLE: typer.colors.YELLOW,
    ExecutionStatus.SKIPPED: None,
}


@app.callback()
@handle_errors
def files_all(
    ctx: typer.Context,
    path: str | None = PathOpt,
    only: str | None = typer.Option(None, "--only", help=f"Run only these checks: {','.join(CHECKS)}"),
    skip: str | None = typer.Option(None, "--skip", help="Run all checks except these."),
    case: str | None = CaseOpt,
    source_host: str | None = HostOpt,
    rules: Path | None = RulesOpt,
    max_files: int = MaxFilesOpt,
) -> None:
    """Run all file checks (or a chosen set with --only / --skip)."""
    if ctx.invoked_subcommand is not None:
        return
    if not path:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=2)
    selection = select_checks(CHECKS, only, skip)
    _execute(path, selection.selected, selection.excluded, case, source_host, rules, max_files)


def _single(check: str):
    @handle_errors
    def command(
        path: str = typer.Option(..., "--path", help="File or folder to investigate."),
        case: str | None = CaseOpt,
        source_host: str | None = HostOpt,
        rules: Path | None = RulesOpt,
        max_files: int = MaxFilesOpt,
    ) -> None:
        _execute(path, [check], [], case, source_host, rules, max_files)

    return command


app.command("hash", help="SHA-256 and MD5 of each file.")(_single("hash"))
app.command("info", help="Metadata, real file type and extension mismatch.")(_single("info"))
app.command("scan", help="Scan with YARA rules.")(_single("scan"))


def _execute(path, checks, excluded, case_id, source_host, rules, max_files) -> None:
    target = validate_evidence_path(path)
    oc, _ = get_or_create_case(case_id, f"files: {target.name or target}")
    result = run_files(
        oc, target, checks, excluded=excluded, source_host=source_host, rules=rules,
        max_files=max_files,
    )
    _print_summary(result)
    failed = [o for o in result.outcomes
              if o.execution.status in (ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT)]
    if failed:
        raise typer.Exit(code=3)  # partial execution


def _print_summary(r: FilesRunResult) -> None:
    mode = r.collection_mode.value
    host_note = " (declared by analyst)" if mode == "import" else ""
    typer.echo()
    typer.secho(f"{r.case.case.id} — files", bold=True)
    typer.echo(f"  path : {r.path}")
    typer.echo(f"  host : {r.host}{host_note}   mode: {mode}")

    typer.echo()
    typer.secho("  Checks", bold=True)
    for o in r.outcomes:
        ex = o.execution
        label = "skipped (your choice)" if ex.error == "excluded_by_user" else ex.status.value
        typer.echo(f"    {o.check:<6}", nl=False)
        typer.secho(f"{label:<22}", fg=_STATUS_COLOR.get(ex.status), nl=False)
        if ex.status is ExecutionStatus.SUCCESS and o.capture is not None:
            extra = f"{o.capture['files_seen']} file(s), {len(o.evidence)} evidence"
            if o.capture.get("truncated"):
                extra += ", STOPPED AT FILE LIMIT (raise it with --max-files)"
            typer.echo(extra)
        else:
            typer.echo("" if ex.error == "excluded_by_user" else (ex.error or ""))

    hashes = r.outcome("hash")
    if hashes and hashes.capture:
        ok = [x for x in hashes.capture["records"] if "sha256" in x]
        if ok:
            typer.echo()
            typer.secho("  Hashes (SHA-256)", bold=True)
            for x in ok[:20]:
                typer.echo(f"    {x['sha256']}  {Path(x['path']).name}")
            if len(ok) > 20:
                typer.echo(f"    ... {len(ok) - 20} more in the case")

    info = r.outcome("info")
    if info and info.capture:
        sus = [x for x in info.capture["records"] if x.get("suspicious_reasons")]
        if sus:
            typer.echo()
            typer.secho("  Suspicious file types", bold=True, fg=typer.colors.YELLOW)
            for x in sus:
                typer.echo(f"    {x['name']}: " + "; ".join(x["suspicious_reasons"]))

    scan = r.outcome("scan")
    if scan and scan.capture:
        typer.echo()
        hits = [e for e in scan.evidence if e.kind.value == "yara_match"]
        if hits:
            typer.secho(f"  YARA matches: {len(hits)}", bold=True, fg=typer.colors.RED)
            for e in hits:
                typer.echo(f"    {e.id}  {e.data['rule']:<28} {Path(e.data['path']).name}")
        else:
            typer.secho("  YARA: no matches with the configured rules", bold=True)

    errors = [e for e in r.evidence if e.status.value == "error"]
    if errors:
        typer.echo()
        typer.secho(f"  Could not read {len(errors)} file(s) — see the case for details",
                    fg=typer.colors.YELLOW)

    typer.echo()
    typer.echo(f"  Evidence stored in {r.case.case.id}: {len(r.evidence)} record(s). "
               f"Raw outputs: {r.case.path / 'raw'}")
