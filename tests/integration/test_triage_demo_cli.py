# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import json

from typer.testing import CliRunner

from atad import triage as tr
from atad.cli.app import app
from tests.unit.test_demo_triage import _Outcome, _Result

runner = CliRunner()


def _run(home, *args):
    return runner.invoke(app, ["--home", str(home), *args])


def test_demo_end_to_end(tmp_path):
    home = tmp_path / "cases"
    r = _run(home, "demo")
    assert r.exit_code == 0, r.output
    assert "SIMULATED" in r.output and "precision 100%" in r.output and "recall    100%" in r.output
    exports = home / "CASE-001" / "exports"
    metrics = json.loads(next(exports.glob("*_demo_metrics_*.json")).read_text(encoding="utf-8"))
    assert metrics["precision"] == 1.0 and metrics["simulated"] is True
    html = next((home / "CASE-001" / "reports").glob("*.html")).read_text(encoding="utf-8")
    assert "Simulated data" in html and "203.0.113.50" in html
    assert list(exports.glob("*.csv")) and list(exports.glob("*.jsonl"))


def _fake_all(monkeypatch, case_status):
    from atad.evidence.models import CollectionMode, Execution, SourceModule

    def run(oc, *a, **kw):
        ex = Execution(case_id=oc.case.id, module=SourceModule.HOST, tool="t",
                       collection_mode=CollectionMode.LOCAL, status=case_status)
        return _Result([_Outcome(ex)])
    for name in ("run_host", "run_log_live", "run_net"):
        monkeypatch.setattr(tr, name, run)
    monkeypatch.setattr(tr, "run_files", lambda oc, path, checks, **kw: run(oc))


def test_triage_creates_case_and_reports(tmp_path, monkeypatch):
    from atad.evidence.models import ExecutionStatus
    _fake_all(monkeypatch, ExecutionStatus.SUCCESS)
    home = tmp_path / "cases"
    r = _run(home, "triage", "--profile", "dfir")
    assert r.exit_code == 0, r.output
    assert "profile dfir" in r.output and "report html" in r.output and ".zip" in r.output
    assert "triage (dfir)" in _run(home, "case", "list").output


def test_triage_partial_exit_code(tmp_path, monkeypatch):
    from atad.evidence.models import ExecutionStatus
    _fake_all(monkeypatch, ExecutionStatus.FAILED)
    r = _run(tmp_path / "cases", "triage")
    assert r.exit_code == 3 and "failed" in r.output


def test_triage_validates_before_creating_anything(tmp_path):
    home = tmp_path / "cases"
    for args, text in [
        (["--profile", "nope"], "--profile"),
        (["--only", "host", "--target", "10.0.0.5"], "--target"),
        (["--skip", "files", "--path", str(tmp_path)], "--path"),
        (["--only", "host,disk"], "unknown"),
        (["--target", "8.8.8.8"], "public"),
        (["--path", str(tmp_path / "missing")], ""),
    ]:
        r = _run(home, "triage", *args)
        assert r.exit_code == 2, (args, r.output)
        assert text in r.output.lower() or text in r.output, (args, r.output)
    assert not home.exists() or not any(home.iterdir())
