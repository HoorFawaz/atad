# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Safe execution of external tools.

Two layers:

* :func:`run_command` — runs one argument list safely and returns what happened.
  No shell, timeout, output size cap, never raises for tool failures.
* :func:`execute_and_record` — runs a command for a case: records the run in the
  ``executions`` table, saves the raw output under ``raw/`` with its SHA-256,
  makes that file read-only and appends a line to ``logs/execution.jsonl``.

Adapters never call ``subprocess`` themselves; they build argument lists and
parse the saved output.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import IO

from atad.cases.manager import OpenCase
from atad.core.exceptions import ValidationError
from atad.core.platform import WINDOWS, current_os, is_elevated
from atad.evidence.integrity import sha256_bytes
from atad.evidence.models import (
    CollectionMode,
    Execution,
    ExecutionStatus,
    SourceModule,
    utc_now,
)

DEFAULT_TIMEOUT = 120.0                  # seconds
DEFAULT_MAX_OUTPUT = 50 * 1024 * 1024    # 50 MiB per stream
STDERR_EXCERPT = 2000                    # characters kept in the database
_READ_CHUNK = 64 * 1024


@dataclass
class CommandResult:
    args: list[str]
    status: ExecutionStatus
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    started_at: datetime
    finished_at: datetime
    duration: float
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ExecutionStatus.SUCCESS


@dataclass
class _Capture:
    limit: int
    data: bytearray = field(default_factory=bytearray)
    truncated: bool = False


def _pump(stream: IO[bytes], cap: _Capture) -> None:
    """Read a pipe to the end, keeping at most ``cap.limit`` bytes.

    The rest is read and thrown away so the child process never blocks on
    a full pipe.
    """
    try:
        while True:
            chunk = stream.read1(_READ_CHUNK)  # type: ignore[attr-defined]
            if not chunk:
                break
            room = cap.limit - len(cap.data)
            if room > 0:
                cap.data.extend(chunk[:room])
            if len(chunk) > room:
                cap.truncated = True
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def validate_args(args: Sequence[str]) -> list[str]:
    """Check an argument list before execution.

    Only real lists of strings are accepted; a single string would be the
    first step towards shell execution, so it is refused.
    """
    if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
        raise ValidationError("command must be a list of arguments, not a string")
    if not args:
        raise ValidationError("command is empty")
    out: list[str] = []
    for a in args:
        if not isinstance(a, str):
            raise ValidationError(f"command argument is not text: {a!r}")
        if "\x00" in a:
            raise ValidationError("command argument contains a NUL byte")
        out.append(a)
    return out


def resolve_executable(name: str) -> str | None:
    """Absolute path of an executable, or None when it is not installed.

    Running the absolute path avoids surprises from the current folder.
    """
    if os.path.isabs(name):
        return name if os.path.isfile(name) and os.access(name, os.X_OK) else None
    return shutil.which(name)


def run_command(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    cwd: str | Path | None = None,
) -> CommandResult:
    """Run ``args`` without a shell and report what happened.

    Tool problems (missing, timeout, non-zero exit, permission) are returned
    as a status, never raised, so one failing tool cannot stop a whole run.
    Invalid input raises :class:`ValidationError`.
    """
    argv = validate_args(args)
    if timeout <= 0:
        raise ValidationError("timeout must be positive")

    started = utc_now()
    t0 = time.monotonic()

    def _result(status: ExecutionStatus, **kw: object) -> CommandResult:
        return CommandResult(
            args=argv,
            status=status,
            started_at=started,
            finished_at=utc_now(),
            duration=time.monotonic() - t0,
            **{"exit_code": None, "stdout": b"", "stderr": b"", **kw},  # type: ignore[arg-type]
        )

    exe = resolve_executable(argv[0])
    if exe is None:
        return _result(ExecutionStatus.UNAVAILABLE, error=f"executable not found: {argv[0]}")
    argv = [exe, *argv[1:]]

    creationflags = 0
    if current_os() == WINDOWS:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            cwd=cwd,
            creationflags=creationflags,
        )
    except PermissionError as exc:
        return _result(ExecutionStatus.FAILED, error=f"permission denied: {exc}")
    except OSError as exc:
        return _result(ExecutionStatus.FAILED, error=f"could not start: {exc}")

    out_cap, err_cap = _Capture(max_output), _Capture(max_output)
    readers = [
        threading.Thread(target=_pump, args=(proc.stdout, out_cap), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, err_cap), daemon=True),
    ]
    for r in readers:
        r.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for r in readers:
        # A grandchild may keep the pipe open; don't hang on it.
        r.join(timeout=5)

    if timed_out:
        status, error = ExecutionStatus.TIMEOUT, f"timed out after {timeout:g}s"
    elif proc.returncode == 0:
        status, error = ExecutionStatus.SUCCESS, None
    else:
        status, error = ExecutionStatus.FAILED, f"exit code {proc.returncode}"

    return _result(
        status,
        exit_code=None if timed_out else proc.returncode,
        stdout=bytes(out_cap.data),
        stderr=bytes(err_cap.data),
        stdout_truncated=out_cap.truncated,
        stderr_truncated=err_cap.truncated,
        error=error,
    )


# --------------------------------------------------------------------------- #
# Case-aware execution
# --------------------------------------------------------------------------- #


@dataclass
class RecordedExecution:
    execution: Execution
    result: CommandResult | None
    raw_path: Path | None


def _safe_name(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in text)[:40] or "tool"


def save_raw(case: OpenCase, execution_id: int, tool: str, data: bytes, suffix: str = "out") -> tuple[str, str]:
    """Write raw output into ``raw/``, make it read-only, return (relative path, sha256)."""
    name = f"EXE-{execution_id:04d}_{_safe_name(tool)}.{suffix}"
    path = case.path / "raw" / name
    with open(path, "xb") as fh:  # 'x': never overwrite existing evidence
        fh.write(data)
    _protect(path)
    return f"raw/{name}", sha256_bytes(data)


def _log_line(case: OpenCase, ex: Execution) -> None:
    entry = {
        "execution_id": ex.id,
        "time": ex.started_at.isoformat(),
        "module": ex.module.value,
        "tool": ex.tool,
        "tool_version": ex.tool_version,
        "command": ex.command,
        "target": ex.target,
        "mode": ex.collection_mode.value,
        "status": ex.status.value,
        "exit_code": ex.exit_code,
        "raw_ref": ex.raw_ref,
        "raw_sha256": ex.raw_sha256,
        "error": ex.error,
    }
    with open(case.path / "logs" / "execution.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def execute_and_record(
    case: OpenCase,
    *,
    module: SourceModule,
    tool: str,
    args: Sequence[str],
    collection_mode: CollectionMode,
    tool_version: str | None = None,
    target: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> RecordedExecution:
    """Run a tool for a case and keep a full, verifiable record of the run."""
    argv = validate_args(args)
    ex = Execution(
        case_id=case.case.id,
        module=module,
        tool=tool,
        tool_version=tool_version,
        command=argv,
        target=target,
        collection_mode=collection_mode,
        status=ExecutionStatus.FAILED,  # until proven otherwise
        elevated=is_elevated(),
    )
    ex_id = case.repo.add_execution(ex)

    result = run_command(argv, timeout=timeout, max_output=max_output)

    raw_ref = raw_sha = None
    raw_path = None
    if result.status is not ExecutionStatus.UNAVAILABLE:
        raw_ref, raw_sha = save_raw(case, ex_id, tool, result.stdout)
        raw_path = case.path / raw_ref
        if result.stderr:
            save_raw(case, ex_id, tool, result.stderr, suffix="err")

    error = result.error
    if result.stdout_truncated:
        error = ((error + "; ") if error else "") + f"stdout truncated at {max_output} bytes"

    final = ex.model_copy(update={
        "id": ex_id,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "status": result.status,
        "exit_code": result.exit_code,
        "raw_ref": raw_ref,
        "raw_sha256": raw_sha,
        "stderr_excerpt": result.stderr.decode("utf-8", "replace")[:STDERR_EXCERPT] or None,
        "error": error,
    })
    case.repo.finish_execution(final)
    _log_line(case, final)
    return RecordedExecution(execution=final, result=result, raw_path=raw_path)


@dataclass
class RecordedCollection:
    execution: Execution
    raw: bytes | None
    raw_path: Path | None


def execute_collector(
    case: OpenCase,
    *,
    module: SourceModule,
    tool: str,
    collection_mode: CollectionMode,
    collect: Callable[[], bytes],
    tool_version: str | None = None,
    target: str | None = None,
    description: list[str] | None = None,
) -> RecordedCollection:
    """Run an in-process collector (hashlib, psutil, ...) with the same record
    keeping as an external tool: execution row, raw capture saved read-only
    with its SHA-256, and a log line.

    ``description`` is stored in place of a command line so the report can
    show what was done (e.g. ``["hash", "C:\\evidence"]``).
    """
    ex = Execution(
        case_id=case.case.id,
        module=module,
        tool=tool,
        tool_version=tool_version,
        command=description,
        target=target,
        collection_mode=collection_mode,
        status=ExecutionStatus.FAILED,
        elevated=is_elevated(),
    )
    ex_id = case.repo.add_execution(ex)
    started = utc_now()
    raw: bytes | None = None
    error: str | None = None
    try:
        raw = collect()
        status = ExecutionStatus.SUCCESS
    except Exception as exc:  # noqa: BLE001 - a collector bug must not stop the whole run
        status = ExecutionStatus.FAILED
        error = f"{type(exc).__name__}: {exc}"

    raw_ref = raw_sha = None
    raw_path = None
    if raw is not None:
        raw_ref, raw_sha = save_raw(case, ex_id, tool, raw, suffix="json")
        raw_path = case.path / raw_ref

    final = ex.model_copy(update={
        "id": ex_id,
        "started_at": started,
        "finished_at": utc_now(),
        "status": status,
        "raw_ref": raw_ref,
        "raw_sha256": raw_sha,
        "error": error,
    })
    case.repo.finish_execution(final)
    _log_line(case, final)
    return RecordedCollection(execution=final, raw=raw, raw_path=raw_path)


def _protect(path: Path) -> None:
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def _sha256_and_size(path: Path) -> tuple[str, int]:
    import hashlib

    h, size = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def execute_to_file(
    case: OpenCase,
    *,
    module: SourceModule,
    tool: str,
    collection_mode: CollectionMode,
    build_args: Callable[[Path], list[str]],
    out_suffix: str,
    tool_version: str | None = None,
    target: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> RecordedExecution:
    """Run a tool that writes its result to a file (e.g. ``wevtutil epl``).

    The tool writes straight into the case's ``raw/`` folder; the file is then
    hashed and made read-only like any other raw output.
    """
    ex = Execution(
        case_id=case.case.id, module=module, tool=tool, tool_version=tool_version,
        target=target, collection_mode=collection_mode,
        status=ExecutionStatus.FAILED, elevated=is_elevated(),
    )
    ex_id = case.repo.add_execution(ex)
    out = case.path / "raw" / f"EXE-{ex_id:04d}_{_safe_name(tool)}.{out_suffix}"
    if out.exists():  # never overwrite evidence
        raise ValidationError(f"raw output already exists: {out}")
    argv = validate_args(build_args(out))
    result = run_command(argv, timeout=timeout)

    status, error = result.status, result.error
    raw_ref = raw_sha = None
    raw_path = None
    if out.is_file():
        raw_sha, _ = _sha256_and_size(out)
        _protect(out)
        raw_ref, raw_path = f"raw/{out.name}", out
    elif status is ExecutionStatus.SUCCESS:
        status, error = ExecutionStatus.FAILED, "tool reported success but wrote no output file"

    final = ex.model_copy(update={
        "id": ex_id, "command": argv,
        "started_at": result.started_at, "finished_at": result.finished_at,
        "status": status, "exit_code": result.exit_code,
        "raw_ref": raw_ref, "raw_sha256": raw_sha,
        "stderr_excerpt": (result.stderr + result.stdout).decode("utf-8", "replace")[:STDERR_EXCERPT] or None
        if status is not ExecutionStatus.SUCCESS else None,
        "error": error,
    })
    case.repo.finish_execution(final)
    _log_line(case, final)
    return RecordedExecution(execution=final, result=result, raw_path=raw_path)


def import_file(
    case: OpenCase,
    *,
    module: SourceModule,
    tool: str,
    source: Path,
    collection_mode: CollectionMode = CollectionMode.IMPORT,
    tool_version: str | None = None,
    target: str | None = None,
) -> RecordedCollection:
    """Copy an evidence file into ``raw/`` (read-only, hashed) before analysis.

    atad always analyses its own copy, never the analyst's original file.
    The copy's hash is computed while copying and checked against the
    source once more afterwards, to catch a file that changed mid-copy.
    """
    import hashlib

    ex = Execution(
        case_id=case.case.id, module=module, tool=tool, tool_version=tool_version,
        command=["import", str(source)], target=target, collection_mode=collection_mode,
        status=ExecutionStatus.FAILED, elevated=is_elevated(),
    )
    ex_id = case.repo.add_execution(ex)
    started = utc_now()
    dest = case.path / "raw" / f"EXE-{ex_id:04d}_{_safe_name(source.stem)}{source.suffix.lower()}"
    raw_ref = raw_sha = error = None
    raw_path = None
    status = ExecutionStatus.SUCCESS
    try:
        h = hashlib.sha256()
        with open(source, "rb") as src, open(dest, "xb") as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                h.update(chunk)
                dst.write(chunk)
        raw_sha = h.hexdigest()
        _protect(dest)
        raw_ref, raw_path = f"raw/{dest.name}", dest
        if _sha256_and_size(source)[0] != raw_sha:
            status, error = ExecutionStatus.FAILED, "source file changed while it was being copied"
    except OSError as exc:
        status, error = ExecutionStatus.FAILED, f"could not copy {source}: {exc.strerror or exc}"

    final = ex.model_copy(update={
        "id": ex_id, "started_at": started, "finished_at": utc_now(), "status": status,
        "raw_ref": raw_ref, "raw_sha256": raw_sha, "error": error,
    })
    case.repo.finish_execution(final)
    _log_line(case, final)
    return RecordedCollection(execution=final, raw=None, raw_path=raw_path)


def record_skipped(
    case: OpenCase,
    *,
    module: SourceModule,
    tool: str,
    collection_mode: CollectionMode,
    status: ExecutionStatus,
    reason: str,
    target: str | None = None,
) -> Execution:
    """Record a check that did not run (skipped by choice/profile, or unavailable).

    This is how the report tells "not run" apart from "ran and found nothing".
    """
    if status not in (ExecutionStatus.SKIPPED, ExecutionStatus.UNAVAILABLE):
        raise ValidationError("record_skipped only accepts skipped or unavailable")
    now = utc_now()
    ex = Execution(
        case_id=case.case.id,
        module=module,
        tool=tool,
        target=target,
        collection_mode=collection_mode,
        started_at=now,
        finished_at=now,
        status=status,
        error=reason,
    )
    ex_id = case.repo.add_execution(ex)
    final = ex.model_copy(update={"id": ex_id})
    _log_line(case, final)
    return final
