# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""atad report / atad export, end to end on SIMULATED data."""

import os
import stat
from pathlib import Path

from typer.testing import CliRunner

from atad.cli.app import app
from atad.modules.logs import runner as lr
from tests.integration.test_correlate_cli import _fake

runner = CliRunner()


def _run(home, *args):
    return runner.invoke(app, ["--home", str(home), *args])


def _case(tmp_path, monkeypatch):
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake)
    home = tmp_path / "cases"
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    assert _run(home, "log", "import", "--path", str(evtx), "--source-host", "LAB-WS-01").exit_code == 0
    iocs = tmp_path / "iocs.txt"
    iocs.write_text("c2.lab.test\n")
    assert _run(home, "ioc", "load", "-c", "CASE-001", "--path", str(iocs)).exit_code == 0
    assert _run(home, "correlate", "-c", "CASE-001").exit_code == 0
    return home


def test_report_and_exports(tmp_path, monkeypatch):
    home = _case(tmp_path, monkeypatch)
    r = _run(home, "report", "-c", "CASE-001")
    assert r.exit_code == 0, r.output
    assert "raw files verified: 2/2" in r.output
    paths = [Path(line.split(None, 1)[1]) for line in r.output.splitlines()
             if line.strip().startswith(("html ", "json "))]
    assert [p.suffix for p in paths] == [".html", ".json"] and all(p.is_file() for p in paths)
    assert "FND-" in paths[0].read_text(encoding="utf-8")

    r = _run(home, "report", "-c", "CASE-001", "--format", "html", "--tlp", "TLP:RED")
    assert r.exit_code == 0, r.output
    html = Path([x for x in r.output.split() if x.endswith(".html")][-1]).read_text(encoding="utf-8")
    assert html.count("TLP:RED") >= 2 and "TLP:AMBER" not in html
    assert _run(home, "report", "-c", "CASE-001", "--tlp", "blue").exit_code == 2

    r = _run(home, "report", "-c", "CASE-001", "--format", "pdf")
    assert r.exit_code == 2 and "--format" in r.output

    r = _run(home, "export", "timeline", "-c", "CASE-001", "--format", "csv")
    assert r.exit_code == 0 and ".csv" in r.output and ".jsonl" not in r.output

    r = _run(home, "export", "case", "-c", "CASE-001")
    assert r.exit_code == 0 and ".zip" in r.output and "sha256" in r.output


def test_report_flags_tampered_evidence(tmp_path, monkeypatch):
    home = _case(tmp_path, monkeypatch)
    raw = next((home / "CASE-001" / "raw").glob("*.txt"))
    os.chmod(raw, stat.S_IWRITE | stat.S_IREAD)
    raw.write_text("changed\n")
    r = _run(home, "report", "-c", "CASE-001", "--format", "html")
    assert r.exit_code == 4
    assert "changed after collection" in r.output
    html = next((home / "CASE-001" / "reports").glob("*.html")).read_text(encoding="utf-8")
    assert "changed after collection" in html and ">Changed<" in html
