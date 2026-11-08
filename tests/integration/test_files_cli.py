# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from pathlib import Path

import pytest
from typer.testing import CliRunner

from atad.cli.app import app

runner = CliRunner()
RULES = Path(__file__).resolve().parents[2] / "rules"


@pytest.fixture
def ev(tmp_path):
    d = tmp_path / "ev"
    d.mkdir()
    (d / "a.txt").write_bytes(b"abc")
    (d / "report.pdf").write_bytes(b"MZ\x90\x00")
    return d


def _run(home, *args):
    return runner.invoke(app, ["--home", str(home), *args])


def test_files_all_creates_case(tmp_path, ev):
    r = _run(tmp_path / "cases", "files", "--path", str(ev), "--rules", str(RULES))
    assert r.exit_code == 0, r.output
    assert "Created CASE-001" in r.output
    assert "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in r.output
    assert "disguised with the extension '.pdf'" in r.output


def test_files_only_into_existing_case(tmp_path, ev):
    home = tmp_path / "cases"
    _run(home, "case", "new", "--name", "x")
    r = _run(home, "files", "--path", str(ev), "--only", "hash", "--case", "CASE-001")
    assert r.exit_code == 0
    assert "skipped (your choice)" in r.output
    assert "Created" not in r.output


def test_single_check_subcommand(tmp_path, ev):
    r = _run(tmp_path / "cases", "files", "info", "--path", str(ev))
    assert r.exit_code == 0
    assert "info" in r.output and "hash" not in r.output.split("Checks")[1].split("\n")[1]


def test_input_errors(tmp_path, ev):
    home = tmp_path / "cases"
    assert _run(home, "files", "--path", str(ev), "--only", "hash", "--skip", "info").exit_code == 2
    assert _run(home, "files", "--path", str(ev), "--only", "virus").exit_code == 2
    assert _run(home, "files", "--path", str(tmp_path / "missing")).exit_code == 2
    assert _run(home, "files").exit_code == 2  # no --path
