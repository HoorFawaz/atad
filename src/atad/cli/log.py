# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""`atad log ...` — Windows event log investigation."""

from __future__ import annotations

from collections import Counter

import typer

from atad.cli.context import get_or_create_case, handle_errors, state
from atad.evidence.models import ExecutionStatus
from atad.modules.checks import select_checks
from atad.modules.logs.evtx_reader import DEFAULT_MAX_EVENTS
from atad.modules.logs.mapping import KEYWORDS
from atad.modules.logs.runner import (
    DEFAULT_HOURS,
    LINUX_CHECKS,
    WINDOWS_CHECKS,
    LogRunResult,
    checks_for_os,
    run_log_import,
    run_log_live,
    search_logs,
    summarize,
)
from atad.utils.validation import validate_evidence_path

app = typer.Typer(
    help="Logs. Windows: Security (4624, 4625, 4688, 4720) and Sysmon (1, 3, 11). "
         "Linux: auth.log/secure (SSH, sudo, useradd), journal, auditd (execve, connect).",
    invoke_without_command=True,
)

CaseOpt = typer.Option(None, "--case", "-c", help="Case id (a new case is created if omitted).")
MaxEventsOpt = typer.Option(DEFAULT_MAX_EVENTS, "--max-events", min=1, max=100_000_000,
                            help="Stop after this many records per log file.")

_COLOR = {
    ExecutionStatus.SUCCESS: typer.colors.GREEN,
    ExecutionStatus.FAILED: typer.colors.RED,
    ExecutionStatus.TIMEOUT: typer.colors.RED,
    ExecutionStatus.UNAVAILABLE: typer.colors.YELLOW,
}


@app.callback()
@handle_errors
def log_live(
    ctx: typer.Context,
    only: str | None = typer.Option(
        None, "--only", help=f"Only these logs. Windows: {','.join(WINDOWS_CHECKS)}; Linux: {','.join(LINUX_CHECKS)}"),
    skip: str | None = typer.Option(None, "--skip", help="All logs except these."),
    hours: int = typer.Option(DEFAULT_HOURS, "--hours", help="How far back to collect."),
    case: str | None = CaseOpt,
    max_events: int = MaxEventsOpt,
) -> None:
    """Collect logs from THIS machine (run atad on the suspect machine, as admin/root)."""
    if ctx.invoked_subcommand is not None:
        return
    selection = select_checks(checks_for_os(), only, skip)
    oc, _ = get_or_create_case(case, "logs: live collection")
    result = run_log_live(oc, selection.selected, excluded=selection.excluded, hours=hours,
                          max_events=max_events)
    _print(result, f"live, last {hours} hour(s)")
    _exit(result)


@app.command("import")
@handle_errors
def log_import(
    path: str = typer.Option(..., "--path", help="Log file or folder copied from the suspect machine."),
    source_host: str = typer.Option(..., "--source-host", help="Machine the logs came from."),
    case: str | None = CaseOpt,
    max_events: int = MaxEventsOpt,
    tz: str = typer.Option("UTC", "--timezone",
                           help="Time zone of syslog lines that have none (UTC, +03:00, Asia/Riyadh)."),
) -> None:
    """Import logs copied from another machine: .evtx, auth.log/secure, journal JSON, audit.log."""
    from atad.modules.logs.linux_runner import parse_timezone

    target = validate_evidence_path(path)
    parse_timezone(tz)                         # validate before creating a case
    oc, _ = get_or_create_case(case, f"logs: {source_host}")
    result = run_log_import(oc, target, source_host, max_events=max_events, tz_name=tz)
    if not result.outcomes:
        typer.secho(f"No supported log files found in {target} "
                    "(.evtx, auth.log/secure, journal JSON, audit.log)", fg=typer.colors.YELLOW)
        raise typer.Exit(code=2)
    _print(result, f"import from {target}")
    _exit(result)


@app.command("search")
@handle_errors
def log_search(
    case: str = typer.Option(..., "--case", "-c", help="Case id."),
    keyword: str = typer.Option(
        ..., "--keyword", "-k",
        help=f"Named search ({', '.join(KEYWORDS)}) or any text (user, IP, program...).",
    ),
    limit: int = typer.Option(50, "--limit", help="Maximum results to show."),
) -> None:
    """Search the log evidence stored in a case."""
    oc = state.manager().open_case(case)
    hits = search_logs(oc, keyword)
    if not hits:
        typer.echo("No matching log events.")
        return
    typer.secho(f"{len(hits)} matching event(s)", bold=True)
    for e in hits[:limit]:
        when = e.event_time.strftime("%Y-%m-%d %H:%M:%S") if e.event_time else "?"
        typer.echo(f"  {e.id}  {when} UTC  {e.summary}")
    if len(hits) > limit:
        typer.echo(f"  ... {len(hits) - limit} more (use --limit)")


# --------------------------------------------------------------------------- #


def _print(r: LogRunResult, label: str) -> None:
    declared = r.collection_mode.value == "import"
    typer.echo()
    typer.secho(f"{r.case.case.id} — logs ({label})", bold=True)
    typer.echo(f"  host : {r.host}{' (declared by analyst)' if declared else ''}"
               f"   mode: {r.collection_mode.value}")

    for o in r.outcomes:
        ex = o.execution
        typer.echo()
        status = "skipped (your choice)" if ex.error == "excluded_by_user" else ex.status.value
        typer.echo(f"  {o.name:<24}", nl=False)
        typer.secho(status, fg=_COLOR.get(ex.status))
        if ex.status is not ExecutionStatus.SUCCESS:
            if ex.error and ex.error != "excluded_by_user":
                typer.echo(f"    {ex.error}")
            continue
        st = o.stats
        if st:
            line = f"    records read: {st.records_read}, stored: {len(o.evidence)}"
            if sum(o.unsupported.values()):
                line += f", other entries ignored: {sum(o.unsupported.values())}"
            typer.echo(line)
            if st.truncated:
                typer.secho("    stopped at the event limit — not every record was read (use --max-events)",
                            fg=typer.colors.YELLOW)
            if st.record_errors:
                typer.secho(f"    unreadable records: {st.record_errors}", fg=typer.colors.YELLOW)
            for err in st.errors[:3]:
                typer.secho(f"    warning: {err}", fg=typer.colors.YELLOW)
        for name, n in summarize(o)["by_event"].items():
            typer.echo(f"      {name:<14} {n}")
        if declared and o.computers:
            names = {c.lower().split(".")[0] for c in o.computers}
            if r.host.lower().split(".")[0] not in names:
                typer.secho(
                    f"    note: events say computer {', '.join(sorted(o.computers))}, "
                    f"not {r.host} — check the source", fg=typer.colors.YELLOW)

    failed = [e for e in r.evidence if e.data.get("outcome") == "failure"]
    if failed:
        ips = Counter(e.data.get("source_ip") or "?" for e in failed)
        typer.echo()
        typer.secho(f"  Failed logons: {len(failed)}", bold=True, fg=typer.colors.YELLOW)
        for ip, n in ips.most_common(5):
            typer.echo(f"    {ip:<20} {n}")

    typer.echo()
    typer.echo(f"  Evidence stored in {r.case.case.id}: {len(r.evidence)} record(s). "
               f"Search with: atad log search --case {r.case.case.id} --keyword failed_login")


def _exit(r: LogRunResult) -> None:
    if any(o.execution.status in (ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT)
           for o in r.outcomes):
        raise typer.Exit(code=3)
