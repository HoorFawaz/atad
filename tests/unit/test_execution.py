# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import json
import os
import stat
import sys

import pytest

from atad.core.exceptions import ValidationError
from atad.core.execution import (
    execute_and_record,
    record_skipped,
    run_command,
    validate_args,
)
from atad.evidence.integrity import sha256_file
from atad.evidence.models import CollectionMode, ExecutionStatus, SourceModule

PY = sys.executable


def py(code: str) -> list[str]:
    return [PY, "-c", code]


# ---------------------------------------------------------------- run_command


def test_success_captures_output():
    r = run_command(py("import sys; print('hello'); print('warn', file=sys.stderr)"))
    assert r.status is ExecutionStatus.SUCCESS and r.exit_code == 0
    assert r.stdout.strip() == b"hello"
    assert r.stderr.strip() == b"warn"
    assert r.duration >= 0 and r.finished_at >= r.started_at


def test_nonzero_exit_is_failed_not_exception():
    r = run_command(py("raise SystemExit(3)"))
    assert r.status is ExecutionStatus.FAILED and r.exit_code == 3


def test_missing_tool_is_unavailable():
    r = run_command(["atad-tool-that-does-not-exist", "--version"])
    assert r.status is ExecutionStatus.UNAVAILABLE
    assert "not found" in r.error


def test_timeout_kills_process():
    r = run_command(py("import time; time.sleep(30)"), timeout=1)
    assert r.status is ExecutionStatus.TIMEOUT
    assert r.duration < 10


def test_output_cap():
    r = run_command(py("import sys; sys.stdout.write('A' * 200000)"), max_output=1000)
    assert r.status is ExecutionStatus.SUCCESS
    assert len(r.stdout) == 1000 and r.stdout_truncated


def test_no_shell_injection(tmp_path):
    marker = tmp_path / "pwned"
    payload = f"x; touch {marker} && echo pwned"
    r = run_command([*py("import sys; print(sys.argv[1])"), payload])
    assert r.ok
    # The payload arrives as one literal argument and nothing else runs.
    assert r.stdout.decode().strip() == payload
    assert not marker.exists()


@pytest.mark.parametrize("bad", ["nmap -sV 10.0.0.1", b"nmap", [], ["nmap", 5], ["nmap", "a\x00b"]])
def test_invalid_args_rejected(bad):
    with pytest.raises(ValidationError):
        validate_args(bad)
    with pytest.raises(ValidationError):
        run_command(bad)


def test_bad_timeout_rejected():
    with pytest.raises(ValidationError):
        run_command(py("pass"), timeout=0)


# ---------------------------------------------------------- execute_and_record


def _run(case, code, **kw):
    return execute_and_record(
        case,
        module=SourceModule.NET,
        tool="fake tool",
        args=py(code),
        collection_mode=CollectionMode.NETWORK,
        target="192.168.1.15",
        **kw,
    )


def test_recorded_run_keeps_raw_output_and_hash(case):
    rec = _run(case, "import sys; print('PORT 22 open'); print('note', file=sys.stderr)")
    ex = rec.execution
    assert ex.id == 1 and ex.status is ExecutionStatus.SUCCESS
    assert ex.raw_ref == "raw/EXE-0001_fake_tool.out"
    assert rec.raw_path.read_bytes().strip() == b"PORT 22 open"
    assert sha256_file(rec.raw_path) == ex.raw_sha256
    assert (case.path / "raw" / "EXE-0001_fake_tool.err").is_file()
    assert ex.stderr_excerpt.strip() == "note"

    # raw evidence is read-only
    mode = os.stat(rec.raw_path).st_mode
    assert not mode & stat.S_IWUSR

    stored = case.repo.list_executions()
    assert len(stored) == 1
    assert stored[0].command == py("import sys; print('PORT 22 open'); print('note', file=sys.stderr)")
    assert stored[0].raw_sha256 == ex.raw_sha256

    log = (case.path / "logs" / "execution.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(log[0])["status"] == "success"


def test_failed_and_timeout_runs_are_recorded(case):
    assert _run(case, "raise SystemExit(2)").execution.status is ExecutionStatus.FAILED
    rec = _run(case, "import time; time.sleep(30)", timeout=1)
    assert rec.execution.status is ExecutionStatus.TIMEOUT
    assert [e.status for e in case.repo.list_executions()] == [
        ExecutionStatus.FAILED, ExecutionStatus.TIMEOUT
    ]


def test_missing_tool_recorded_as_unavailable_without_raw_file(case):
    rec = execute_and_record(
        case, module=SourceModule.NET, tool="nmap", args=["atad-no-such-nmap", "-oX", "-"],
        collection_mode=CollectionMode.NETWORK,
    )
    assert rec.execution.status is ExecutionStatus.UNAVAILABLE
    assert rec.raw_path is None
    assert list((case.path / "raw").iterdir()) == []


def test_truncation_is_noted(case):
    rec = _run(case, "import sys; sys.stdout.write('B' * 5000)", max_output=100)
    assert "truncated" in rec.execution.error
    assert len(rec.raw_path.read_bytes()) == 100


def test_skipped_vs_unavailable(case):
    s = record_skipped(case, module=SourceModule.NET, tool="nslookup",
                       collection_mode=CollectionMode.NETWORK,
                       status=ExecutionStatus.SKIPPED, reason="excluded_by_user")
    u = record_skipped(case, module=SourceModule.LOG, tool="sysmon",
                       collection_mode=CollectionMode.LOCAL,
                       status=ExecutionStatus.UNAVAILABLE, reason="Sysmon not installed")
    assert (s.status, u.status) == (ExecutionStatus.SKIPPED, ExecutionStatus.UNAVAILABLE)
    assert [e.error for e in case.repo.list_executions()] == ["excluded_by_user", "Sysmon not installed"]
    with pytest.raises(ValidationError):
        record_skipped(case, module=SourceModule.NET, tool="x",
                       collection_mode=CollectionMode.NETWORK,
                       status=ExecutionStatus.SUCCESS, reason="no")
