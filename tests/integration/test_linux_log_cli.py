# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Linux logs end to end (SIMULATED samples): import, correlate, live collection."""

import os
import sys
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from atad.cli.app import app
from atad.evidence.models import ExecutionStatus
from atad.modules.logs import linux_runner as lxr
from atad.modules.logs import runner as lr
from tests.fixtures import linux_logs as fx

runner = CliRunner()


def _run(home, *args):
    return runner.invoke(app, ["--home", str(home), *args])


def _folder(tmp_path):
    d = tmp_path / "copied-from-web01"
    d.mkdir()
    (d / "auth.log").write_text(fx.AUTH_BSD)
    (d / "audit.log").write_text(fx.AUDIT)
    (d / "journal.json").write_text(fx.JOURNAL)
    (d / "notes.txt").write_text("not a log\n")
    ts = datetime(2026, 11, 7, 12, 0, tzinfo=UTC).timestamp()
    os.utime(d / "auth.log", (ts, ts))
    return d


def test_import_linux_logs_and_correlate(tmp_path):
    home = tmp_path / "cases"
    r = _run(home, "log", "import", "--path", str(_folder(tmp_path)), "--source-host", "web01",
             "--timezone", "UTC")
    assert r.exit_code == 0, r.output
    assert "auth ssh_failed" in r.output and "audit execve" in r.output and "journal service_started" in r.output
    assert "notes.txt" not in r.output
    assert "Failed logons: 6" in r.output          # 5 in auth.log + 1 in the journal
    assert "time zone" in r.output                  # assumed-time warning is shown

    r = _run(home, "log", "search", "-c", "CASE-001", "--keyword", "sudo")
    assert "sudo by deploy as root" in r.output

    iocs = tmp_path / "iocs.txt"
    iocs.write_text("203.0.113.50\n")
    _run(home, "ioc", "load", "-c", "CASE-001", "--path", str(iocs))
    r = _run(home, "correlate", "-c", "CASE-001")
    assert "Repeated failed logons then success from 203.0.113.9" in r.output
    fid = next(x.split()[0] for x in r.output.splitlines() if "then success from 203.0.113.9" in x)
    r1 = _run(home, "findings", "-c", "CASE-001", "--show", fid).output
    # the 10:01:02 failure is in auth.log and in the journal: counted once
    assert "5 failed logons" in r1 and "counted once" in r1
    assert "curl connected to known indicator 203.0.113.50" in r.output


def test_import_bad_timezone(tmp_path):
    r = _run(tmp_path / "cases", "log", "import", "--path", str(_folder(tmp_path)),
             "--source-host", "web01", "--timezone", "Mars/Olympus")
    assert r.exit_code == 2 and "time zone" in r.output
    assert not (tmp_path / "cases").exists()


@pytest.mark.skipif(sys.platform.startswith("win"), reason="fake journalctl is a POSIX script")
def test_live_linux_sources(case, tmp_path, monkeypatch):
    auth = tmp_path / "auth.log"
    auth.write_text(fx.AUTH_ISO)
    audit = tmp_path / "audit.log"
    audit.write_text(fx.AUDIT)
    os.chmod(audit, 0)                                   # unreadable, like for a normal user
    fake = tmp_path / "journalctl"
    fake.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write({fx.JOURNAL!r})\n")
    fake.chmod(0o755)
    monkeypatch.setattr(lr, "current_os", lambda: "linux")
    monkeypatch.setattr(lxr, "AUTH_FILES", (str(auth),))
    monkeypatch.setattr(lxr, "AUDIT_FILE", str(audit))
    monkeypatch.setattr(lxr.shutil, "which", lambda name: str(fake))
    monkeypatch.setattr(lxr, "utc_now", lambda: datetime(2026, 11, 7, 12, 0, tzinfo=UTC))

    r = lr.run_log_live(case, ["auth", "journal", "audit"], hours=24)
    by = {o.name: o for o in r.outcomes}
    assert by["auth (auth.log)"].execution.status is ExecutionStatus.SUCCESS
    assert len(by["auth (auth.log)"].evidence) == 2
    j = by["journal"]
    assert j.execution.command[1:3] == ["-o", "json"] and "SYSLOG_IDENTIFIER=sshd" in j.execution.command
    assert len(j.evidence) == 4
    if os.geteuid() != 0:                                  # root can read a mode-0 file
        assert by["audit (audit.log)"].execution.status is ExecutionStatus.UNAVAILABLE
        assert "root" in by["audit (audit.log)"].execution.error

    old = lr.run_log_live(case, ["auth"], hours=1)        # window ends 12:00; events are ~10:00
    assert old.outcomes[0].evidence == []


def test_linux_checks_off_linux_are_unavailable(case, monkeypatch):
    monkeypatch.setattr(lr, "current_os", lambda: "windows")
    r = lr.run_log_live(case, ["auth", "journal"])
    assert {o.execution.status for o in r.outcomes} == {ExecutionStatus.UNAVAILABLE}
