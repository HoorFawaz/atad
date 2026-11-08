# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from atad.adapters.base import ParseContext, ToolInfo
from atad.core.exceptions import ValidationError
from atad.evidence.integrity import sha256_file
from atad.evidence.models import CollectionMode, EvidenceKind, ExecutionStatus
from atad.modules.logs import runner as lr
from atad.modules.logs.evtx_reader import parse_event_xml, parse_system_time
from atad.modules.logs.mapping import SECURITY, event_to_evidence
from tests.fixtures import events as fx


def ctx(**kw):
    base = {"case_id": "CASE-001", "host": "LAB-WS-01", "collection_mode": CollectionMode.LOCAL,
                "simulated": True, "tool_version": "0.8.1"}
    base.update(kw)
    return ParseContext(**base)


def ev_of(xml):
    return event_to_evidence(parse_event_xml(xml), ctx())


def obs(e, kind):
    return {o.value for o in e.observables if o.type.value == kind}


# ---------------------------------------------------------------- time parse


@pytest.mark.parametrize("raw,expected", [
    ("2016-07-08 18:12:51.681641+00:00", datetime(2016, 7, 8, 18, 12, 51, 681641, tzinfo=UTC)),
    ("2026-11-07T10:06:00.1234567Z", datetime(2026, 11, 7, 10, 6, 0, 123456, tzinfo=UTC)),
    ("2026-11-07 10:06:00", datetime(2026, 11, 7, 10, 6, tzinfo=UTC)),  # EVTX is UTC
])
def test_parse_system_time(raw, expected):
    assert parse_system_time(raw) == expected


def test_parse_system_time_bad():
    assert parse_system_time("yesterday") is None and parse_system_time("") is None


# ---------------------------------------------------------------- XML parse


def test_parse_event_xml():
    e = parse_event_xml(fx.SUCCESS_LOGON)
    assert (e["channel"], e["event_id"], e["record_id"], e["computer"]) == (SECURITY, 4624, 200, "LAB-WS-01")
    assert e["data"]["IpAddress"] == "10.66.0.9"


@pytest.mark.parametrize("bad", ["not xml", "<Event></Event>", "<a><System><EventID>x</EventID></System></a>"])
def test_parse_event_xml_rejects(bad):
    assert parse_event_xml(bad) is None


# ------------------------------------------------------------------ mapping


def test_failed_logon():
    e = ev_of(fx.failed_logon(1))
    assert e.kind is EvidenceKind.LOGON and e.data["outcome"] == "failure"
    assert e.summary == "Failed logon for LAB\\bob (Network) from 10.66.0.9"
    assert obs(e, "ip") == {"10.66.0.9"} and obs(e, "user") == {"lab\\bob"}
    assert obs(e, "hostname") == {"attacker-pc", "lab-ws-01"}
    assert e.event_time == datetime(2026, 11, 7, 10, 2, 1, tzinfo=UTC)


def test_success_logon_rdp():
    e = ev_of(fx.SUCCESS_LOGON)
    assert e.data["outcome"] == "success" and "RDP" in e.data["logon_type"]
    assert "c:\\windows\\system32\\svchost.exe" in obs(e, "path")


def test_process_4688_hex_pid():
    e = ev_of(fx.PROCESS_4688)
    assert e.kind is EvidenceKind.PROCESS
    assert e.data["pid"] == 0x1018 and obs(e, "pid") == {"4120"}
    assert "-EncodedCommand" in e.data["command_line"]


def test_user_created():
    e = ev_of(fx.USER_CREATED)
    assert e.kind is EvidenceKind.LOG_EVENT
    assert e.summary == "User account created: LAB\\svc-backup2 by LAB\\bob"


def test_sysmon_process_hashes():
    e = ev_of(fx.SYSMON_PROCESS)
    assert e.kind is EvidenceKind.PROCESS
    assert obs(e, "sha256") == {"b" * 64} and obs(e, "md5") == {"a" * 32}
    assert obs(e, "process_guid") == {"{aaaa1111-0000-0000-0000-000000000001}"}


def test_sysmon_network():
    e = ev_of(fx.SYSMON_NETWORK)
    assert e.kind is EvidenceKind.NETWORK_CONNECTION
    assert e.summary == "invoice.pdf.exe connected to c2.lab.test:443"
    assert obs(e, "ip") == {"10.66.0.9"} and obs(e, "domain") == {"c2.lab.test"}


def test_sysmon_file_created():
    e = ev_of(fx.SYSMON_FILE)
    assert "c:\\users\\bob\\appdata\\roaming\\update.ps1" in obs(e, "path")


def test_same_process_linked_across_sysmon_events():
    guids = [obs(ev_of(x), "process_guid") for x in (fx.SYSMON_PROCESS, fx.SYSMON_NETWORK, fx.SYSMON_FILE)]
    assert guids[0] == guids[1] == guids[2]


def test_unsupported_event_ignored():
    assert ev_of(fx.UNSUPPORTED) is None


def test_bad_values_do_not_break_event():
    xml = fx.event(SECURITY, 4625, "2026-11-07 10:00:00+00:00",
                   {"TargetUserName": "bob", "IpAddress": "not-an-ip", "LogonType": "3"})
    e = ev_of(xml)
    assert e is not None and obs(e, "ip") == set()


def test_import_mode_keeps_declared_host():
    e = event_to_evidence(parse_event_xml(fx.SUCCESS_LOGON),
                          ctx(collection_mode=CollectionMode.IMPORT, host="WS-07", host_declared=True))
    assert e.host == "WS-07" and e.host_declared and e.data["computer"] == "LAB-WS-01"


# -------------------------------------------------------- runner (no evtx)


def _fake_reader(xmls):
    def fake(path, stats, max_events):
        for x in xmls:
            stats.records_read += 1
            yield x
    return fake


@pytest.fixture
def fake_evtx(tmp_path):
    p = tmp_path / "copied" / "Security.evtx"
    p.parent.mkdir()
    p.write_bytes(b"ElfFile\x00" + b"\x00" * 64)  # header only; reading is faked
    return p


def test_import_flow(case, fake_evtx, monkeypatch):
    xmls = [fx.failed_logon(i) for i in range(5)] + [fx.SUCCESS_LOGON, fx.UNSUPPORTED, "garbage"]
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake_reader(xmls))
    original = fake_evtx.read_bytes()

    r = lr.run_log_import(case, fake_evtx.parent, "WS-07")
    o = r.outcomes[0]
    assert o.execution.status is ExecutionStatus.SUCCESS
    assert len(o.evidence) == 6 and sum(o.unsupported.values()) == 1
    assert o.stats.record_errors == 1  # "garbage"

    # atad works on its own read-only copy; the original is untouched
    copy = case.path / o.execution.raw_ref
    assert copy.read_bytes() == original == fake_evtx.read_bytes()
    assert sha256_file(copy) == o.execution.raw_sha256
    assert not os.stat(copy).st_mode & stat.S_IWUSR
    assert all(e.raw_ref == o.execution.raw_ref and e.host == "WS-07" for e in o.evidence)

    # stored in time order
    times = [e.event_time for e in o.evidence]
    assert times == sorted(times)


def test_import_rejects_non_evtx(case, tmp_path):
    bad = tmp_path / "fake.evtx"
    bad.write_bytes(b"MZ not a log")
    r = lr.run_log_import(case, bad, "WS-07")
    assert r.outcomes[0].execution.status is ExecutionStatus.UNAVAILABLE
    assert list((case.path / "raw").iterdir()) == []


def test_corrupted_file_reported_not_crashing(case, fake_evtx):
    # real python-evtx on a header-only file
    r = lr.run_log_import(case, fake_evtx, "WS-07")
    o = r.outcomes[0]
    assert o.execution.status is ExecutionStatus.SUCCESS  # the copy worked
    assert o.evidence == [] and o.stats.errors  # reading problem is reported


def test_search(case, fake_evtx, monkeypatch):
    xmls = [fx.failed_logon(i) for i in range(3)] + [fx.SUCCESS_LOGON, fx.PROCESS_4688]
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake_reader(xmls))
    lr.run_log_import(case, fake_evtx, "WS-07")
    assert len(lr.search_logs(case, "failed_login")) == 3
    assert len(lr.search_logs(case, "process_created")) == 1
    assert len(lr.search_logs(case, "10.66.0.9")) == 4      # free text
    assert len(lr.search_logs(case, "EncodedCommand")) == 1
    with pytest.raises(ValidationError):
        lr.search_logs(case, "  ")


# ----------------------------------------------------------------- live mode


def test_xpath_and_args():
    xp = lr.build_xpath({4625, 4624}, 2)
    assert xp == "*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 7200000]]]"
    args = lr.build_export_args("C:\\Windows\\System32\\wevtutil.exe", SECURITY, Path("out.evtx"), 1)
    assert args[1:3] == ["epl", "Security"] and args[-1] == "/ow:false"
    assert args[4].startswith("/q:*[System[(EventID=4624")


def test_live_not_on_windows_is_unavailable(case, monkeypatch):
    monkeypatch.setattr(lr, "current_os", lambda: "linux")
    r = lr.run_log_live(case, ["security", "sysmon"])
    assert {o.execution.status for o in r.outcomes} == {ExecutionStatus.UNAVAILABLE}


@pytest.mark.skipif(sys.platform.startswith("win"), reason="fake tool is a POSIX script")
def test_live_flow_with_fake_wevtutil(case, tmp_path, monkeypatch):
    fake = tmp_path / "wevtutil"
    fake.write_text(
        f"#!{sys.executable}\nimport sys\n"
        "open(sys.argv[3], 'wb').write(b'ElfFile\\x00' + b'\\x00' * 64)\n"
    )
    fake.chmod(0o755)
    monkeypatch.setattr(lr, "current_os", lambda: "windows")
    monkeypatch.setattr(lr.Wevtutil, "detect",
                        lambda self: ToolInfo(name="wevtutil", available=True, path=str(fake)))
    monkeypatch.setattr(lr.Sysmon, "detect",
                        lambda self: ToolInfo(name="sysmon", available=False, reason="not installed"))
    monkeypatch.setattr(lr, "iter_evtx_xml", _fake_reader([fx.failed_logon(1), fx.SUCCESS_LOGON]))

    r = lr.run_log_live(case, ["security", "sysmon"], hours=2)
    sec, sysm = r.outcomes
    assert sec.execution.status is ExecutionStatus.SUCCESS
    assert sec.execution.command[1:3] == ["epl", "Security"]
    assert (case.path / sec.execution.raw_ref).is_file()
    assert len(sec.evidence) == 2 and all(not e.host_declared for e in sec.evidence)
    assert sysm.execution.status is ExecutionStatus.UNAVAILABLE
    assert "Sysmon" in sysm.execution.error


def test_live_skip_and_hours_validation(case, monkeypatch):
    monkeypatch.setattr(lr, "current_os", lambda: "linux")
    r = lr.run_log_live(case, ["security"], excluded=["sysmon"])
    assert [o.execution.error for o in r.outcomes][1] == "excluded_by_user"
    with pytest.raises(ValidationError):
        lr.run_log_live(case, ["security"], hours=0)


@pytest.mark.skipif(not os.environ.get("ATAD_EVTX_SAMPLE"), reason="set ATAD_EVTX_SAMPLE to a real .evtx")
def test_real_evtx_sample(case):
    r = lr.run_log_import(case, Path(os.environ["ATAD_EVTX_SAMPLE"]), "SAMPLE-HOST")
    o = r.outcomes[0]
    assert o.execution.status is ExecutionStatus.SUCCESS and o.stats.records_read > 0
