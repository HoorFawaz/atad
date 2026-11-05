# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from typer.testing import CliRunner

from atad.cli.app import app

runner = CliRunner()


def _run(home, *args):
    return runner.invoke(app, ["--home", str(home), *args])


def test_case_workflow(tmp_path):
    home = tmp_path / "cases"

    r = _run(home, "case", "list")
    assert r.exit_code == 0 and "No cases yet" in r.output

    r = _run(home, "case", "new", "--name", "Lab workstation", "--profile", "dfir", "--simulated")
    assert r.exit_code == 0, r.output
    assert "Created CASE-001" in r.output and "SIMULATED" in r.output

    r = _run(home, "scope", "add", "--case", "CASE-001", "--target", "192.168.1.15")
    assert r.exit_code == 0 and "Added to scope" in r.output

    r = _run(home, "case", "show", "case-001")
    assert r.exit_code == 0
    assert "dfir" in r.output and "192.168.1.15" in r.output

    r = _run(home, "case", "list")
    assert "CASE-001" in r.output and "Lab workstation" in r.output


def test_errors_have_exit_codes_not_tracebacks(tmp_path):
    home = tmp_path / "cases"
    r = _run(home, "case", "show", "CASE-404")
    assert r.exit_code == 1 and "not found" in r.output
    assert "Traceback" not in r.output

    _run(home, "case", "new", "--name", "x")
    r = _run(home, "scope", "add", "--case", "CASE-001", "--target", "-sV")
    assert r.exit_code == 2

    r = _run(home, "scope", "add", "--case", "CASE-001", "--target", "8.8.8.8")
    assert r.exit_code == 2 and "public" in r.output


def test_version():
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0 and "atad 0.1.0" in r.output
