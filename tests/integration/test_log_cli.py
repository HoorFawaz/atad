# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from typer.testing import CliRunner

from atad.cli.app import app
from atad.modules.logs import runner as lr
from tests.fixtures import events as fx

runner = CliRunner()


def _fake(path, stats, max_events):
    for x in [fx.failed_logon(i) for i in range(5)] + [fx.SUCCESS_LOGON]:
        stats.records_read += 1
        yield x


def test_import_and_search(tmp_path, monkeypatch):
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake)
    src = tmp_path / "Security.evtx"
    src.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    home = tmp_path / "cases"

    r = runner.invoke(app, ["--home", str(home), "log", "import", "--path", str(src),
                            "--source-host", "LAB-WS-01"])
    assert r.exit_code == 0, r.output
    assert "Security 4625" in r.output and "Failed logons: 5" in r.output
    assert "10.66.0.9" in r.output

    r = runner.invoke(app, ["--home", str(home), "log", "search", "--case", "CASE-001",
                            "--keyword", "failed_login"])
    assert r.exit_code == 0 and "5 matching event(s)" in r.output


def test_host_mismatch_note(tmp_path, monkeypatch):
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake)
    src = tmp_path / "Security.evtx"
    src.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    r = runner.invoke(app, ["--home", str(tmp_path / "c"), "log", "import", "--path", str(src),
                            "--source-host", "OTHER-PC"])
    assert "check the source" in r.output


def test_import_errors(tmp_path):
    home = tmp_path / "cases"
    empty = tmp_path / "empty"
    empty.mkdir()
    r = runner.invoke(app, ["--home", str(home), "log", "import", "--path", str(empty),
                            "--source-host", "X"])
    assert r.exit_code == 2 and "No supported log files" in r.output
    r = runner.invoke(app, ["--home", str(home), "log", "--only", "security", "--skip", "sysmon"])
    assert r.exit_code == 2
