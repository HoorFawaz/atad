# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import sys

import pytest
from typer.testing import CliRunner

from atad.adapters.base import ExternalTool
from atad.cli.app import app
from atad.core.tool_registry import ToolRegistry

runner = CliRunner()


class Present(ExternalTool):
    name = "present"
    purpose = "a tool that exists"
    executables = (sys.executable,)
    version_pattern = r"Python (\S+)"
    required = True


class OptionalMissing(ExternalTool):
    name = "optmissing"
    executables = ("atad-not-here",)


class RequiredMissing(ExternalTool):
    name = "reqmissing"
    executables = ("atad-not-here-either",)
    required = True


@pytest.fixture
def fake_registry(monkeypatch):
    def use(*adapters):
        monkeypatch.setattr("atad.cli.doctor.make_registry", lambda: ToolRegistry(list(adapters)))
    return use


def test_doctor_ready_when_only_optional_missing(fake_registry, tmp_path):
    fake_registry(Present(), OptionalMissing())
    r = runner.invoke(app, ["--home", str(tmp_path), "doctor"])
    assert r.exit_code == 0, r.output
    assert "present" in r.output and "ok" in r.output
    assert "optmissing" in r.output and "missing" in r.output
    assert "Ready" in r.output


def test_doctor_fails_when_required_missing(fake_registry, tmp_path):
    fake_registry(Present(), RequiredMissing())
    r = runner.invoke(app, ["--home", str(tmp_path), "doctor"])
    assert r.exit_code == 1
    assert "Missing required: reqmissing" in r.output


def test_doctor_records_into_case(fake_registry, tmp_path):
    home = tmp_path / "cases"
    runner.invoke(app, ["--home", str(home), "case", "new", "--name", "x"])
    fake_registry(Present(), OptionalMissing())
    r = runner.invoke(app, ["--home", str(home), "doctor", "--case", "CASE-001"])
    assert r.exit_code == 0 and "Recorded in CASE-001" in r.output

    from atad.cases.manager import CaseManager
    tools = CaseManager(home).open_case("CASE-001").repo.list_tools()
    assert {(t["name"], t["available"]) for t in tools} == {("present", 1), ("optmissing", 0)}


def test_real_doctor_runs():
    """The real catalog must never crash, whatever is installed."""
    r = runner.invoke(app, ["doctor"])
    assert r.exit_code in (0, 1)
    assert "Traceback" not in r.output
    assert "psutil" in r.output and "nmap" in r.output
