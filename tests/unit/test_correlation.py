# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Correlation on a labelled, SIMULATED scenario.

Every rule has at least one true case and one decoy that looks similar but
must NOT produce a finding. The test checks the exact set of findings, so a
missed link (recall) or an extra one (precision) fails it.
"""

from datetime import datetime, timedelta, timezone

import pytest

from atad.correlation.config import CorrelationConfig
from atad.correlation.engine import correlate
from atad.correlation.rules import host_key
from atad.evidence.models import (
    CollectionMode,
    Confidence,
    Evidence,
    FindingCategory,
    Ioc,
    Observable,
    Severity,
)

T0 = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)
WS1, WS2 = "LAB-WS-01", "LAB-WS-02"
DROPPER = "C:\\Users\\bob\\AppData\\Local\\Temp\\invoice.pdf.exe"
SHA_DROPPER = "1" * 64
SHA_UNUSED = "2" * 64
GUID = "{aaaa1111-0000-0000-0000-000000000001}"


def ev(kind, module, host=WS1, t=None, data=None, obs=(), summary=None):
    return Evidence(case_id="X", kind=kind, source_module=module, source_tool="test",
                    collection_mode=CollectionMode.IMPORT, host=host, host_declared=True, event_time=t,
                    summary=summary or f"{kind} test", data=data or {},
                    observables=[Observable(type=k, value=v) for k, v in obs], simulated=True)


def logon(ip, outcome, t, user="lab\\bob"):
    return ev("logon", "log", t=t, data={"outcome": outcome, "source_ip": ip, "user": user},
              obs=[("ip", ip), ("user", user)])


def build(case):
    cid = case.case.id
    items = []
    # R1 true: 6 failures in 4 minutes, then success
    items += [logon("10.66.0.9", "failure", T0 + timedelta(seconds=40 * i)) for i in range(6)]
    items += [logon("10.66.0.9", "success", T0 + timedelta(minutes=6))]
    # R1 decoy: only 4 failures before the success
    items += [logon("10.66.0.20", "failure", T0 + timedelta(seconds=10 * i)) for i in range(4)]
    items += [logon("10.66.0.20", "success", T0 + timedelta(minutes=1))]
    # R1 true (no success): 6 failures and no success -> medium finding
    items += [logon("10.66.0.30", "failure", T0 + timedelta(seconds=5 * i)) for i in range(6)]
    # R1 decoy: 6 failures spread over an hour (outside the 10-minute window)
    items += [logon("10.66.0.40", "failure", T0 - timedelta(minutes=12 * i)) for i in range(1, 7)]
    items += [logon("10.66.0.40", "success", T0)]

    # S1 true: encoded PowerShell (4688)
    items.append(ev("process", "log", t=T0 + timedelta(minutes=7), data={
        "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        obs=[("path", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")]))
    # S1 decoy: -ExecutionPolicy is not an encoded command
    items.append(ev("process", "host", data={
        "cmdline": "powershell.exe -ExecutionPolicy Bypass -File backup.ps1"}))

    # Dropper: Sysmon 1 process with hash and GUID
    items.append(ev("process", "log", t=T0 + timedelta(minutes=7, seconds=30),
                    data={"image": DROPPER, "command_line": "invoice.pdf.exe"},
                    obs=[("path", DROPPER), ("pid", "4120"), ("process_guid", GUID),
                         ("sha256", SHA_DROPPER)]))
    # R2 true: Sysmon 3 from the dropper to a high-confidence IOC (also a URL-IOC domain)
    items.append(ev("network_connection", "log", t=T0 + timedelta(minutes=8),
                    data={"image": DROPPER, "destination_port": "443"},
                    obs=[("path", DROPPER), ("pid", "4120"), ("process_guid", GUID),
                         ("domain", "evil.example"), ("ip", "203.0.113.50")]))
    # R2 decoy: connection to an IOC range, but no process record to link it to
    items.append(ev("network_connection", "host", data={"exe": "C:\\Windows\\svchost.exe"},
                    obs=[("pid", "999"), ("path", "C:\\Windows\\svchost.exe"),
                         ("ip", "198.51.100.7")]))

    # Files: the dropper is disguised (S2) and matches YARA (YARA, R3)
    items.append(ev("file", "files", data={"name": "invoice.pdf.exe", "path": DROPPER,
                                           "suspicious_reasons": ["double extension"]},
                    obs=[("path", DROPPER), ("sha256", SHA_DROPPER)]))
    items.append(ev("yara_match", "files",
                    data={"path": DROPPER, "sha256": SHA_DROPPER, "rule": "Demo_Dropper",
                          "meta": {"severity": "high"}},
                    obs=[("path", DROPPER), ("sha256", SHA_DROPPER)]))
    # S2 decoy: ordinary file
    items.append(ev("file", "files", data={"name": "notes.txt", "path": "C:\\notes.txt",
                                           "suspicious_reasons": []},
                    obs=[("path", "C:\\notes.txt")]))
    # R3 decoy: YARA match on a file that never ran
    items.append(ev("yara_match", "files",
                    data={"path": "C:\\tools\\unused.dll", "sha256": SHA_UNUSED, "rule": "Demo_Lib"},
                    obs=[("path", "C:\\tools\\unused.dll"), ("sha256", SHA_UNUSED)]))

    # R4 true: the brute-force IP also shows up in a live connection (host module)
    items.append(ev("network_connection", "host", data={"exe": "C:\\Windows\\System32\\svchost.exe"},
                    obs=[("ip", "10.66.0.9")]))
    # R4 / IOC decoy: this machine's own address
    items.append(ev("interface", "net", obs=[("ip", "10.66.0.5")]))

    # R5 decoy: only two suspicious findings on WS2
    items.append(ev("process", "log", host=WS2, t=T0 - timedelta(hours=1),
                    data={"command_line": "powershell -enc AAAA"}))

    case.repo.add_evidence_many([e.model_copy(update={"case_id": cid}) for e in items])
    case.repo.add_iocs([
        Ioc(case_id=cid, type="ip", value="203.0.113.50", source="c2.txt", confidence=Confidence.HIGH),
        Ioc(case_id=cid, type="url", value="http://evil.example/payload", source="c2.txt"),
        Ioc(case_id=cid, type="cidr", value="198.51.100.0/24", source="ranges.txt",
            confidence=Confidence.LOW),
        Ioc(case_id=cid, type="sha256", value=SHA_DROPPER, source="hashes.txt"),
        Ioc(case_id=cid, type="ip", value="192.0.2.99", source="c2.txt"),   # decoy: not seen
        Ioc(case_id=cid, type="ip", value="10.66.0.5", source="c2.txt"),    # decoy: own address
    ])


EXPECTED = {
    ("IOC", "Known indicator seen: 203.0.113.50"),
    ("IOC", "Known indicator seen: http://evil.example/payload"),
    ("IOC", "Known indicator seen: 198.51.100.0/24"),
    ("IOC", f"Known indicator seen: {SHA_DROPPER[:39]}…"),
    ("YARA", "YARA rule 'Demo_Dropper' matched invoice.pdf.exe"),
    ("YARA", "YARA rule 'Demo_Lib' matched unused.dll"),
    ("S1", "Encoded PowerShell command on LAB-WS-01"),
    ("S1", "Encoded PowerShell command on LAB-WS-02"),
    ("S2", "Disguised file: invoice.pdf.exe"),
    ("R1", "Repeated failed logons then success from 10.66.0.9"),
    ("R1", "Repeated failed logons from 10.66.0.30 (no success seen)"),
    ("R2", "invoice.pdf.exe connected to known indicator 203.0.113.50"),
    ("R3", "YARA-flagged file was executed: invoice.pdf.exe"),
    ("R5", "Possible coordinated activity on LAB-WS-01"),
}


@pytest.fixture
def scenario(case):
    build(case)
    return case


def _labels(findings):
    return {(f.rule_id, f.title) for f in findings if f.rule_id != "R4"}


def test_precision_and_recall(scenario):
    r = correlate(scenario.repo)
    got = _labels(r.findings)
    tp = got & EXPECTED
    precision = len(tp) / len(got)
    recall = len(tp) / len(EXPECTED)
    assert (precision, recall) == (1.0, 1.0), (
        f"missed: {sorted(EXPECTED - got)}\nextra: {sorted(got - EXPECTED)}")


def test_r4_pivots(scenario):
    r = correlate(scenario.repo)
    by_id = {f.id: f for f in r.findings}
    pivots = [f for f in r.findings if f.rule_id == "R4"]
    origins = {by_id[f.title.split()[2]].rule_id for f in pivots}
    # R1's IP seen in a live connection; the YARA file path seen in Sysmon 3
    assert origins == {"R1", "YARA"}
    assert all(f.category is FindingCategory.CORRELATED for f in pivots)
    assert not any("10.66.0.5" in f.rationale for f in r.findings)


def test_details(scenario):
    r = correlate(scenario.repo)
    f = {x.rule_id + x.title: x for x in r.findings}
    r1 = f["R1Repeated failed logons then success from 10.66.0.9"]
    assert r1.severity is Severity.HIGH and len(r1.evidence_ids) == 7
    assert "6 failed logons" in r1.rationale and "lab\\bob" in r1.rationale
    r2 = f["R2invoice.pdf.exe connected to known indicator 203.0.113.50"]
    assert "ProcessGuid" in r2.rationale and r2.confidence is Confidence.HIGH
    r3 = f["R3YARA-flagged file was executed: invoice.pdf.exe"]
    assert r3.confidence is Confidence.HIGH and "SHA-256" in r3.rationale
    yara = f["YARAYARA rule 'Demo_Dropper' matched invoice.pdf.exe"]
    assert yara.severity is Severity.HIGH
    url = f["IOCKnown indicator seen: http://evil.example/payload"]
    assert "domain evil.example" in url.rationale
    r5 = f["R5Possible coordinated activity on LAB-WS-01"]
    assert r5.category is FindingCategory.HYPOTHESIS and "hypothesis" in r5.rationale


def test_rerun_replaces_and_ids_grow(scenario):
    first = correlate(scenario.repo)
    second = correlate(scenario.repo)
    assert second.removed == len(first.findings)
    assert len(scenario.repo.list_findings()) == len(second.findings)
    assert _labels(first.findings) == _labels(second.findings)
    assert min(f.id for f in second.findings) > max(f.id for f in first.findings)


def test_timeline(scenario):
    r = correlate(scenario.repo)
    tl = scenario.repo.list_timeline()
    assert len(tl) == r.timeline_events
    times = [e["event_time"] for e in tl]
    assert times == sorted(times)
    markers = [e for e in tl if e["finding_id"]]
    assert markers and all(e["description"].startswith(f"[{e['finding_id']} ·") for e in markers)
    # Evidence without an event time (e.g. files) is not placed on the timeline
    assert all(e["evidence_id"] is None or e["event_time"] for e in tl)


def test_thresholds_and_disabled_rules(scenario):
    r = correlate(scenario.repo, CorrelationConfig(r1_min_failures=4, disabled_rules=("S2", "R5")))
    rules = r.by_rule
    assert rules["R1"] == 3          # 10.66.0.20 now counts too
    assert "S2" not in rules and "R5" not in rules


def test_r1_without_success_is_medium(scenario):
    r = correlate(scenario.repo)
    f = next(x for x in r.findings if "10.66.0.30" in x.title)
    assert f.severity is Severity.MEDIUM and len(f.evidence_ids) == 6
    assert "No successful logon" in f.rationale


def test_r1_long_attack_is_one_finding(case):
    # 40 failures, one every 30 s (20 minutes), then a success: one finding, not several
    cid = case.case.id
    items = [logon("10.66.0.77", "failure", T0 + timedelta(seconds=30 * i)) for i in range(40)]
    items.append(logon("10.66.0.77", "success", T0 + timedelta(minutes=21)))
    case.repo.add_evidence_many([e.model_copy(update={"case_id": cid}) for e in items])
    r1 = [f for f in correlate(case.repo).findings if f.rule_id == "R1"]
    assert len(r1) == 1 and "40 failed logons" in r1[0].rationale
    assert "success" in r1[0].title


def test_r4_same_source_other_event_type(case):
    # Brute-force IP later contacted by a process: both from the event logs
    cid = case.case.id
    items = [logon("10.66.0.9", "failure", T0 + timedelta(seconds=i)) for i in range(5)]
    items.append(logon("10.66.0.9", "success", T0 + timedelta(minutes=2)))
    items.append(logon("10.66.0.9", "failure", T0 + timedelta(hours=3)))  # repeat, not a link
    items.append(ev("network_connection", "log", t=T0 + timedelta(minutes=5),
                    data={"image": DROPPER}, obs=[("ip", "10.66.0.9")]))
    stored = case.repo.add_evidence_many([e.model_copy(update={"case_id": cid}) for e in items])
    pivots = [f for f in correlate(case.repo).findings if f.rule_id == "R4"]
    assert len(pivots) == 1
    p4 = pivots[0]
    assert p4.title.endswith("found in other events") and p4.confidence is Confidence.LOW
    assert "same source, different event type" in p4.rationale
    assert stored[-1].id in p4.evidence_ids and stored[-2].id not in p4.evidence_ids


def _disguised(sha, t=None):
    return ev("file", "files", t=t, data={"name": "a.pdf.exe", "path": "C:\\a.pdf.exe",
                                          "suspicious_reasons": ["double extension"]},
              obs=[("path", "C:\\a.pdf.exe"), ("sha256", sha)])


def _r4_from_s2(case, *items):
    cid = case.case.id
    case.repo.add_evidence_many([e.model_copy(update={"case_id": cid}) for e in items])
    return [f for f in correlate(case.repo).findings
            if f.rule_id == "R4" and "a.pdf.exe" in f.rationale]


def test_r4_hash_independent_source_is_high(case):
    sha = "3" * 64
    found = _r4_from_s2(case, _disguised(sha),
                        ev("process", "host", data={"exe": "C:\\x.exe"}, obs=[("sha256", sha)]))
    assert found and found[0].confidence is Confidence.HIGH
    assert "exact hash match means the same file" in found[0].rationale


def test_r4_hash_same_source_other_event_is_medium(case):
    sha = "3" * 64
    found = _r4_from_s2(case, _disguised(sha, T0),
                        ev("log_event", "files", t=T0 + timedelta(minutes=1),
                           obs=[("sha256", sha)]))
    assert found and found[0].confidence is Confidence.MEDIUM


def test_r4_two_views_of_one_file_are_not_a_link(case):
    # A file's info record and its YARA record describe one object, not two events.
    sha = "3" * 64
    found = _r4_from_s2(case, _disguised(sha, T0),
                        ev("yara_match", "files", data={"path": "C:\\a.pdf.exe", "sha256": sha,
                                                        "rule": "R"}, obs=[("sha256", sha)]))
    assert found == []


def test_r4_ip_independent_is_medium(scenario):
    r = correlate(scenario.repo)
    by_id = {f.id: f for f in r.findings}
    p4 = next(f for f in r.findings if f.rule_id == "R4"
              and by_id[f.title.split()[2]].rule_id == "R1")
    assert p4.confidence is Confidence.MEDIUM and "independent source" in p4.rationale
    assert "can be shared" in p4.rationale


def _autostart(name, exe, kind="registry_run", host=WS1):
    from atad.modules.host.collector import _USER_WRITABLE
    reasons = (["starts from a user-writable folder"]
               if any(d in exe.lower() for d in _USER_WRITABLE) else [])
    return ev("persistence", "host", host=host,
              data={"type": kind, "name": name, "executable": exe,
                    "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "suspicious_reasons": reasons},
              obs=[("path", exe)])


def test_s3_user_writable_autostart(case):
    cid = case.case.id
    items = [
        _autostart("WinUpdate", "C:\\Users\\sara\\AppData\\Roaming\\upd.exe"),
        _autostart("WinUpdate2", "C:\\Users\\sara\\AppData\\Roaming\\upd.exe",
                   kind="startup_folder"),                                    # same program
        _autostart("Svc", "C:\\Users\\Public\\svc.exe", kind="service"),
        _autostart("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe"),
        _autostart("OneDrive", "C:\\Users\\sara\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"),
    ]
    case.repo.add_evidence_many([e.model_copy(update={"case_id": cid}) for e in items])
    s3 = {f.title: f for f in correlate(case.repo).findings if f.rule_id == "S3"}
    assert set(s3) == {"Auto-start from a user-writable folder: upd.exe",
                       "Auto-start from a user-writable folder: svc.exe"}
    upd = s3["Auto-start from a user-writable folder: upd.exe"]
    assert len(upd.evidence_ids) == 2
    assert upd.severity is Severity.MEDIUM and upd.confidence is Confidence.LOW
    assert "T1547.001" in upd.rationale
    assert "T1543.003" in s3["Auto-start from a user-writable folder: svc.exe"].rationale


def test_s3_linked_by_r4_to_the_file_creation(case):
    cid = case.case.id
    exe = "C:\\Users\\sara\\AppData\\Roaming\\upd.exe"
    items = [_autostart("WinUpdate", exe),
             ev("log_event", "log", t=T0, data={"target_file": exe}, obs=[("path", exe)])]
    case.repo.add_evidence_many([e.model_copy(update={"case_id": cid}) for e in items])
    findings = correlate(case.repo).findings
    s3 = next(f for f in findings if f.rule_id == "S3")
    r4 = [f for f in findings if f.rule_id == "R4" and s3.id in f.title]
    assert r4 and "independent source" in r4[0].rationale


def test_no_iocs_no_ioc_findings(case):
    assert correlate(case.repo).findings == []


def test_host_key():
    assert host_key("LAB-WS-01.lab.local") == host_key("lab-ws-01")
    assert host_key("10.0.0.5") == "10.0.0.5"
