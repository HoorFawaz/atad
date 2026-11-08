# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""End to end: logs → IOC list → correlate → findings → timeline (SIMULATED data)."""

from typer.testing import CliRunner

from atad.cli.app import app
from atad.modules.logs import runner as lr
from tests.fixtures import events as fx

runner = CliRunner()

EVENTS = ([fx.failed_logon(i) for i in range(5)] + [fx.SUCCESS_LOGON, fx.PROCESS_4688,
          fx.USER_CREATED, fx.SYSMON_PROCESS, fx.SYSMON_NETWORK, fx.SYSMON_FILE])


def _fake(path, stats, max_events):
    for x in EVENTS:
        stats.records_read += 1
        yield x


def _run(home, *args):
    return runner.invoke(app, ["--home", str(home), *args])


def test_full_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake)
    home = tmp_path / "cases"
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    assert _run(home, "log", "import", "--path", str(evtx), "--source-host", "LAB-WS-01").exit_code == 0

    iocs = tmp_path / "lab-iocs.txt"
    iocs.write_text("# simulated lab indicators\nc2[.]lab[.]test\n" + "b" * 64 +
                    "\n192.0.2.1\nnot-an-ioc!\n", encoding="utf-8")
    r = _run(home, "ioc", "load", "--case", "CASE-001", "--path", str(iocs), "--confidence", "high")
    assert r.exit_code == 0, r.output
    assert "read: 3   new: 3" in r.output and "rejected lines: 1" in r.output
    assert "raw/EXE-" in r.output

    r = _run(home, "ioc", "load", "--case", "CASE-001", "--path", str(iocs))
    assert "new: 0   already loaded: 3" in r.output

    r = _run(home, "ioc", "list", "--case", "CASE-001")
    assert "3 indicator(s)" in r.output and "c2.lab.test" in r.output

    r = _run(home, "ioc", "check", "--case", "CASE-001")
    assert "2 indicator(s) seen" in r.output and "192.0.2.1" not in r.output

    r = _run(home, "correlate", "--case", "CASE-001")
    assert r.exit_code == 0, r.output
    for rule in ("IOC 2", "R1 1", "R2 1", "R4 2", "S1 1", "R5 1"):
        assert rule in r.output, r.output

    r = _run(home, "findings", "--case", "CASE-001", "--min-severity", "high")
    assert "Repeated failed logons then success from 10.66.0.9" in r.output
    assert "Encoded PowerShell" not in r.output  # medium

    r = _run(home, "findings", "--case", "CASE-001")
    fid = next(line.split()[0] for line in r.output.splitlines() if "connected to known" in line)
    r = _run(home, "findings", "--case", "CASE-001", "--show", fid)
    assert "Why" in r.output and "ProcessGuid" in r.output and "c2.lab.test" in r.output
    assert "EVD-" in r.output

    r = _run(home, "timeline", "--case", "CASE-001")
    assert r.exit_code == 0 and "UTC" in r.output
    lines = [x for x in r.output.splitlines() if x.startswith("  2026-")]
    stamps = [x[:21] for x in lines]
    assert stamps == sorted(stamps)
    assert any(fid in x for x in lines)

    r = _run(home, "timeline", "--case", "CASE-001", "--findings-only")
    assert all("FND-" in x for x in r.output.splitlines()[1:] if x.strip())

    # Running again replaces, never duplicates
    first = _run(home, "findings", "--case", "CASE-001").output.splitlines()[0]
    _run(home, "correlate", "--case", "CASE-001")
    assert _run(home, "findings", "--case", "CASE-001").output.splitlines()[0] == first


def test_bad_config_and_missing_finding(tmp_path):
    home = tmp_path / "cases"
    assert _run(home, "case", "new", "--name", "t").exit_code == 0
    cfg = tmp_path / "c.yaml"
    cfg.write_text("nope: 1\n")
    r = _run(home, "correlate", "--case", "CASE-001", "--config", str(cfg))
    assert r.exit_code == 2 and "unknown setting" in r.output
    r = _run(home, "findings", "--case", "CASE-001", "--show", "FND-9999")
    assert r.exit_code == 2
    r = _run(home, "timeline", "--case", "CASE-001")
    assert "Timeline is empty" in r.output


def test_correlate_sigma_options(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake)
    home = tmp_path / "cases"
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    _run(home, "log", "import", "--path", str(evtx), "--source-host", "LAB-WS-01")
    rules = Path(__file__).resolve().parents[1] / "fixtures" / "sigmahq"
    r = _run(home, "correlate", "-c", "CASE-001", "--sigma", str(rules))
    assert r.exit_code == 0, r.output
    assert "Sigma: 7 rule(s) loaded from 8 file(s)" not in r.output       # README is not a rule
    assert "Sigma: 7 rule(s) loaded from 7 file(s), 0 skipped" in r.output
    assert "Sigma: Suspicious Encoded PowerShell Command Line" in r.output
    assert "Sigma: Local User Creation" in r.output
    r = _run(home, "correlate", "-c", "CASE-001", "--no-sigma")
    assert "Sigma: no rules" in r.output and "Sigma: Suspicious" not in r.output
    r = _run(home, "correlate", "-c", "CASE-001", "--sigma", str(tmp_path / "missing"))
    assert r.exit_code == 2 and "not found" in r.output
