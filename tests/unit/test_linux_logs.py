# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from datetime import UTC, datetime, timedelta, timezone

from atad.adapters.base import ParseContext
from atad.evidence.models import CollectionMode, EvidenceKind
from atad.modules.logs import linux as lx
from tests.fixtures import linux_logs as fx

MTIME = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
UTC3 = timezone(timedelta(hours=3))


def _ctx():
    return ParseContext(case_id="CASE-001", host="web01", collection_mode=CollectionMode.IMPORT,
                        host_declared=True, simulated=True, tool="test")


def test_syslog_bsd_lines():
    st = lx.SyslogStats()
    recs = list(lx.iter_syslog(fx.AUTH_BSD, file_mtime=MTIME, tz=UTC, tz_label="UTC", stats=st))
    assert [r.event for r in recs] == ["ssh_failed"] * 5 + ["ssh_accepted", "sudo", "user_created",
                                                            "sudo_failed"]
    assert st.unparsed == 1 and st.unsupported == 2 and st.assumed_times == 11
    assert recs[0].time == datetime(2026, 11, 7, 10, 1, 2, tzinfo=UTC)
    assert "time zone UTC" in recs[0].time_basis
    assert recs[1].fields["invalid_user"] is True and recs[1].fields["user"] == "admin"
    assert recs[6].fields["command_line"] == "/usr/sbin/useradd -m backup"
    assert recs[8].fields["attempts"] == 3


def test_syslog_timezone_and_year_rollover():
    recs = list(lx.iter_syslog(fx.AUTH_BSD, file_mtime=MTIME, tz=UTC3, tz_label="+03:00"))
    assert recs[0].time == datetime(2026, 11, 7, 7, 1, 2, tzinfo=UTC)
    jan = datetime(2027, 1, 2, tzinfo=UTC)          # December logs read in January
    dec = list(lx.iter_syslog("Dec 31 23:59:00 h sshd[1]: Accepted password for a from 10.0.0.1 port 1 ssh2",
                              file_mtime=jan, tz=UTC, tz_label="UTC"))
    assert dec[0].time.year == 2026


def test_syslog_iso_lines_are_exact():
    recs = list(lx.iter_syslog(fx.AUTH_ISO, file_mtime=MTIME, tz=UTC, tz_label="UTC"))
    assert recs[0].time == datetime(2026, 11, 7, 10, 1, 2, 123456, tzinfo=UTC)
    assert all(r.time_basis == "exact" for r in recs)
    assert recs[1].fields["source_ip"] == "2001:db8::7" and recs[1].fields["method"] == "publickey"


def test_journal():
    st = lx.SyslogStats()
    recs = list(lx.iter_journal(fx.JOURNAL, st))
    assert [r.event for r in recs] == ["ssh_failed", "ssh_accepted", "service_started", "sudo"]
    assert recs[0].time == datetime(2026, 11, 7, 10, 1, 2, tzinfo=UTC)
    assert recs[2].fields["unit"] == "backdoor.service"
    assert recs[3].fields["command_line"] == "/usr/bin/id"           # byte-array MESSAGE
    assert st.unparsed == 1 and st.unsupported == 1


def test_audit_execve_and_connect():
    st = lx.SyslogStats()
    recs = list(lx.iter_audit(fx.AUDIT, st, host="web01"))
    assert [r.event for r in recs] == ["execve", "connect"]
    ex, conn = recs
    assert ex.fields["argv"] == ["curl", "-s", "-o", "/tmp/.x sh.elf"]     # hex argument decoded
    assert ex.fields["image"] == "/usr/bin/curl" and ex.fields["pid"] == 2290 and ex.fields["cwd"] == "/root"
    assert conn.fields["destination_ip"] == "203.0.113.50" and conn.fields["destination_port"] == 443
    assert st.unparsed == 1 and st.unsupported == 2      # AF_UNIX connect, USER_LOGIN


def test_evidence_and_correlation_keys():
    recs = list(lx.iter_syslog(fx.AUTH_BSD, file_mtime=MTIME, tz=UTC, tz_label="UTC"))
    recs += list(lx.iter_audit(fx.AUDIT, host="web01"))
    ev = [lx.record_to_evidence(r, _ctx()) for r in recs]
    logons = [e for e in ev if e.kind is EvidenceKind.LOGON]
    assert len(logons) == 6 and logons[0].data["outcome"] == "failure"
    assert logons[0].data["source_ip"] == "203.0.113.9"
    proc = next(e for e in ev if e.kind is EvidenceKind.PROCESS)
    conn = next(e for e in ev if e.kind is EvidenceKind.NETWORK_CONNECTION)
    assert {o.type.value for o in proc.observables} >= {"path", "pid"}
    assert {(o.type.value, o.value) for o in conn.observables} >= {("ip", "203.0.113.50"), ("pid", "2290")}
    assert all(e.data["time_basis"] for e in ev)


def test_detect_format(tmp_path):
    cases = {"a.evtx": b"ElfFile\x00rest", "j.json": fx.JOURNAL.encode(), "audit.log": fx.AUDIT.encode(),
             "auth.log": fx.AUTH_BSD.encode(), "x.txt": b"hello"}
    got = {}
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
        got[name] = lx.detect_format(tmp_path / name)
    assert got == {"a.evtx": "evtx", "j.json": "journal", "audit.log": "audit",
                   "auth.log": "syslog", "x.txt": None}
