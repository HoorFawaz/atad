# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import os
import sys

import pytest

from atad.adapters.base import ParseContext
from atad.evidence.models import CollectionMode, EvidenceKind, ExecutionStatus
from atad.modules.host import collector as hc
from atad.modules.host import runner as hr


def ctx():
    return ParseContext(case_id="CASE-001", host="LAB-WS-01", collection_mode=CollectionMode.LOCAL,
                        simulated=True)


@pytest.mark.parametrize("cmd,exe", [
    ('"C:\\Program Files\\App\\app.exe" --silent', "C:\\Program Files\\App\\app.exe"),
    ("C:\\Windows\\system32\\svchost.exe -k netsvcs", "C:\\Windows\\system32\\svchost.exe"),
    ("C:\\Users\\bob\\AppData\\Roaming\\up date.ps1 -x", "C:\\Users\\bob\\AppData\\Roaming\\up date.ps1"),
    ("rundll32.exe shell32.dll,Control_RunDLL", "rundll32.exe"),
    ("", None), (None, None),
])
def test_executable_from_command(cmd, exe):
    assert hc.executable_from_command(cmd) == exe


def test_process_flags():
    assert hc.process_flags("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", "x.exe", True) == [
        "runs from a user-writable folder"]
    assert "PowerShell with an encoded command" in hc.process_flags(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -nop -enc SQBFAFgA", True)
    assert hc.process_flags("/usr/bin/sshd", "/usr/sbin/sshd -D", False) == [
        "program file no longer exists on disk"]
    assert hc.process_flags("C:\\Windows\\explorer.exe", "explorer.exe", True) == []


def test_startup_mapping():
    cap = {"records": [
        {"location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "type": "registry_run",
         "name": "Updater", "command": "C:\\Users\\bob\\AppData\\Roaming\\update.exe -q",
         "executable": "C:\\Users\\bob\\AppData\\Roaming\\update.exe",
         "suspicious_reasons": ["starts from a user-writable folder"]},
        {"location": "services", "type": "service", "name": "Spooler",
         "command": "C:\\Windows\\System32\\spoolsv.exe", "executable": "C:\\Windows\\System32\\spoolsv.exe",
         "suspicious_reasons": []},
    ]}
    ev = hc.startup_to_evidence(cap, ctx())
    assert [e.kind for e in ev] == [EvidenceKind.PERSISTENCE] * 2
    assert ev[0].summary.startswith("Run key: Updater -> update.exe — SUSPICIOUS")
    assert ev[1].summary == "Auto-start service: Spooler -> spoolsv.exe"


def test_users_mapping_ip_or_name():
    cap = {"records": [
        {"user": "bob", "terminal": "pts/0", "from_host": "10.66.0.9", "started_utc": None},
        {"user": "amy", "terminal": None, "from_host": "ws-02", "started_utc": None},
    ]}
    a, b = hc.users_to_evidence(cap, ctx())
    assert {o.type.value for o in a.observables} == {"user", "ip"}
    assert {o.type.value for o in b.observables} == {"user", "hostname"}


def test_connection_listen_vs_outbound():
    cap = {"records": [
        {"protocol": "tcp", "family": "ipv4", "local_ip": "0.0.0.0", "local_port": 445,
         "remote_ip": None, "remote_port": None, "state": "LISTEN", "pid": 4, "process": "System", "exe": None},
        {"protocol": "tcp", "family": "ipv4", "local_ip": "192.168.1.15", "local_port": 50123,
         "remote_ip": "10.66.0.9", "remote_port": 443, "state": "ESTABLISHED", "pid": 4120,
         "process": "invoice.pdf.exe", "exe": "C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.pdf.exe"},
    ]}
    listen, out = hc.connections_to_evidence(cap, ctx())
    assert listen.kind is EvidenceKind.OPEN_PORT
    assert out.kind is EvidenceKind.NETWORK_CONNECTION
    assert {o.value for o in out.observables if o.type.value == "ip"} == {"10.66.0.9"}


# --------------------------------------------------------- real local collection


def test_real_collection_on_this_machine(case):
    r = hr.run_host(case, ["info", "processes", "connections", "users"])
    for check in ("info", "processes", "connections", "users"):
        assert r.outcome(check).execution.status is ExecutionStatus.SUCCESS, check
    procs = r.outcome("processes").evidence
    assert any(e.data["pid"] == os.getpid() for e in procs)          # finds itself
    me = next(e for e in procs if e.data["pid"] == os.getpid())
    if me.data.get("exe"):
        assert me.data["sha256"] and len(me.data["sha256"]) == 64     # program hashed
    assert all(e.host == r.host and not e.host_declared for e in r.evidence)


def test_startup_on_other_os_is_unavailable(case, monkeypatch):
    monkeypatch.setattr(hr, "current_os", lambda: "macos")
    r = hr.run_host(case, ["startup"], excluded=["info"])
    assert r.outcome("startup").execution.status is ExecutionStatus.UNAVAILABLE
    assert r.outcome("info").excluded_by_user


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows registry")
def test_real_startup_on_windows(case):
    r = hr.run_host(case, ["startup"])
    assert r.outcome("startup").execution.status is ExecutionStatus.SUCCESS
