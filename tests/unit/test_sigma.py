# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import base64
from pathlib import Path

import pytest
import yaml

from atad.correlation.engine import correlate
from atad.demo.builder import build_demo
from atad.evidence.models import FindingCategory, Severity
from atad.modules.logs import runner as lr
from atad.sigma.engine import run_sigma
from atad.sigma.rules import SigmaError, _b64_offsets, compile_rule, load_rules

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sigmahq"
OWN_RULES = Path(__file__).resolve().parents[2] / "rules" / "sigma"


def rule(detection: dict, logsource=None, **extra):
    doc = {"title": "t", "logsource": logsource or {"product": "windows"}, "detection": detection, **extra}
    return compile_rule(doc, "x.yml", "0" * 64)


# --------------------------------------------------------------- values


@pytest.mark.parametrize("det,event,expected", [
    ({"s": {"Image": "C:\\Windows\\cmd.exe"}, "condition": "s"}, {"Image": "c:\\windows\\CMD.EXE"}, True),
    ({"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"}, {"Image": "C:\\x\\cmd.exe"}, True),
    ({"s": {"Image|startswith": "C:\\Users\\"}, "condition": "s"}, {"Image": "D:\\Users\\a"}, False),
    ({"s": {"CommandLine|contains": "whoami"}, "condition": "s"}, {"CommandLine": "cmd /c WHOAMI /all"}, True),
    ({"s": {"CommandLine": "*-enc *"}, "condition": "s"}, {"CommandLine": "ps -enc AAAA"}, True),
    ({"s": {"CommandLine": "a?c"}, "condition": "s"}, {"CommandLine": "abc"}, True),
    ({"s": {"CommandLine": "a\\*c"}, "condition": "s"}, {"CommandLine": "abc"}, False),
    ({"s": {"CommandLine|contains|all": ["net", "user", "/add"]}, "condition": "s"},
     {"CommandLine": "net user bob P@ss /add"}, True),
    ({"s": {"CommandLine|contains|all": ["net", "/add"]}, "condition": "s"}, {"CommandLine": "net user"}, False),
    ({"s": {"Image|endswith": ["\\a.exe", "\\b.exe"]}, "condition": "s"}, {"Image": "C:\\b.exe"}, True),
    ({"s": {"File|re": "^x\\d+$"}, "condition": "s"}, {"File": "X12"}, False),       # re is case-sensitive
    ({"s": {"File|re|i": "^x\\d+$"}, "condition": "s"}, {"File": "X12"}, True),
    ({"s": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "s"}, {"DestinationIp": "10.2.3.4"}, True),
    ({"s": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "s"}, {"DestinationIp": "8.8.8.8"}, False),
    ({"s": {"CommandLine|windash|contains": " -nop "}, "condition": "s"}, {"CommandLine": "ps /nop x"}, True),
    ({"s": {"CommandLine|windash|contains": " -nop "}, "condition": "s"}, {"CommandLine": "ps \u2013nop x"}, True),
    ({"s": {"ParentUser": None}, "condition": "s"}, {"Image": "x"}, True),
    ({"s": {"User|fieldref": "ParentUser"}, "condition": "s"}, {"User": "A", "ParentUser": "a"}, True),
    ({"s": {"User|exists": True}, "condition": "s"}, {"Image": "x"}, False),
    ({"s": {"Port|gte": 1024}, "condition": "s"}, {"Port": "8080"}, True),
    ({"s": {"EventID": 4625}, "condition": "s"}, {"EventID": 4625}, True),
    ({"k": ["mimikatz", "sekurlsa"], "condition": "k"}, {"_keywords_text": "ran SEKURLSA::logonpasswords"}, True),
    ({"s": {"type": "EXECVE"}, "condition": "s"}, {"type": ["CWD", "EXECVE", "SYSCALL"]}, True),
])
def test_values(det, event, expected):
    assert rule(det).match(event) is expected


def test_base64offset_finds_text_at_any_offset():
    variants = _b64_offsets("IEX (")
    for prefix in ("", "a", "ab"):
        enc = base64.b64encode((prefix + "IEX (New-Object").encode()).decode()
        assert any(v in enc for v in variants)


# ------------------------------------------------------------- conditions

SELS = {"a": {"X": "1"}, "b": {"Y": "1"}, "c": {"Z": "1"}, "filter_1": {"F": "1"}, "filter_2": {"G": "1"}}


@pytest.mark.parametrize("cond,event,expected", [
    ("a and b or c", {"Z": "1"}, True),                  # and binds tighter than or
    ("a and (b or c)", {"Z": "1"}, False),
    ("a and not b", {"X": "1", "Y": "1"}, False),
    ("not a", {}, True),
    ("1 of filter_*", {"G": "1"}, True),
    ("all of filter_*", {"G": "1"}, False),
    ("a and not 1 of filter_*", {"X": "1"}, True),
    ("all of them", {"X": "1", "Y": "1", "Z": "1", "F": "1", "G": "1"}, True),
    ("2 of them", {"X": "1", "Y": "1"}, True),
])
def test_conditions(cond, event, expected):
    assert rule({**SELS, "condition": cond}).match(event) is expected


def test_condition_list_is_or():
    r = rule({**SELS, "condition": ["a", "b"]})
    assert r.match({"Y": "1"}) and not r.match({"Z": "1"})


@pytest.mark.parametrize("det,reason", [
    ({"s": {"X": "1"}, "condition": "s | count() > 5"}, "aggregation"),
    ({"s": {"X|utf16le": "1"}, "condition": "s"}, "modifier"),
    ({"s": {"X": "1"}, "condition": "t"}, "unknown selection"),
    ({"s": {"X": "1"}, "condition": "1 of nothing*"}, "matches no selection"),
    ({"s": {"X": "1"}, "condition": "(s"}, r"missing '\)'"),
    ({"s": {"X": "1"}}, "no condition"),
])
def test_unsupported_rules_are_rejected_with_a_reason(det, reason):
    with pytest.raises(SigmaError, match=reason):
        rule(det)


def test_loader_reports_skipped(tmp_path):
    (tmp_path / "ok.yml").write_text(yaml.safe_dump({"title": "ok", "logsource": {"product": "windows"},
                                                     "detection": {"s": {"X": 1}, "condition": "s"}}))
    (tmp_path / "agg.yml").write_text(yaml.safe_dump({"title": "agg", "logsource": {},
                                                      "detection": {"s": {"X": 1}, "condition": "s | count() > 2"}}))
    (tmp_path / "old.yml").write_text(yaml.safe_dump({"title": "old", "status": "deprecated", "logsource": {},
                                                      "detection": {"s": {"X": 1}, "condition": "s"}}))
    (tmp_path / "bad.yml").write_text("title: [unclosed\n")
    rep = load_rules(tmp_path)
    assert [r.title for r in rep.rules] == ["ok"] and rep.files == 4
    reasons = " ".join(r for _, r in rep.skipped)
    assert "aggregation" in reasons and "deprecated" in reasons and "invalid YAML" in reasons


# ------------------------------------------------- public SigmaHQ rules (DRL 1.1)

# Labelled expectations on the SIMULATED demo case: rule title -> what it must match.
EXPECTED_DEMO = {
    "Suspicious Encoded PowerShell Command Line": ["EncodedCommand"],
    "PowerShell Base64 Encoded IEX Cmdlet": ["EncodedCommand"],          # base64offset
    "Suspicious Double Extension File Execution": ["invoice.pdf.exe"],
    "Suspicious Double Extension Files": ["invoice.pdf.exe"],            # re|i on TargetFilename
    "Local User Creation": ["svc-backup2"],                              # Security 4720
    "Change PowerShell Policies to an Insecure Level": ["backup.ps1"],   # true match of that rule
}


def _summaries(case, f):
    return " | ".join(case.repo.get_evidence(x).summary + " " + str(case.repo.get_evidence(x).data)
                      for x in f.evidence_ids)


def test_public_rules_load_without_skips():
    rep = load_rules(FIXTURES)
    assert len(rep.rules) == 7 and rep.skipped == []


def test_public_rules_on_demo_case(manager):
    b = build_demo(manager)
    run = run_sigma(b.case.case.id, b.case.repo.list_evidence(), FIXTURES)
    found = {f.title.removeprefix("Sigma: "): f for f in run.findings}
    expected = dict(EXPECTED_DEMO)                    # Sigma does not depend on YARA
    assert set(found) == set(expected), sorted(found)
    for title, needles in expected.items():
        text = _summaries(b.case, found[title])
        assert all(n.lower() in text.lower() for n in needles), (title, text[:300])
    # decoys: the real PDF and the plain text file never match the double-extension rules
    for title in ("Suspicious Double Extension Files", "Suspicious Double Extension File Execution"):
        text = _summaries(b.case, found[title])
        assert "Q3-report.pdf" not in text and "notes.txt" not in text
    # the backup script is not reported as encoded PowerShell
    assert "backup.ps1" not in _summaries(b.case, found["Suspicious Encoded PowerShell Command Line"])
    # DRL 1.1: messages based on a match keep the rule's author
    assert "Florian Roth" in found["Suspicious Encoded PowerShell Command Line"].rationale
    assert found["Local User Creation"].category is FindingCategory.OBSERVATION       # level low


def test_public_and_own_rules_on_linux_logs(case, tmp_path):
    from tests.integration.test_linux_log_cli import _folder
    lr.run_log_import(case, _folder(tmp_path), "web01", tz_name="UTC")
    ev = case.repo.list_evidence()
    public = {f.title for f in run_sigma(case.case.id, ev, FIXTURES).findings}
    own = {f.title: f for f in run_sigma(case.case.id, ev, OWN_RULES).findings}
    assert public == {"Sigma: Curl Usage on Linux"}
    assert set(own) == {"Sigma: Download Into a Temporary Folder With curl or wget",
                        "Sigma: New Local User Created"}
    assert own["Sigma: Download Into a Temporary Folder With curl or wget"].severity is Severity.MEDIUM


def test_correlate_with_sigma_replaces_on_rerun(manager):
    b = build_demo(manager)
    first = correlate(b.case.repo, sigma=FIXTURES)
    assert first.sigma.matched_rules == 6
    sig = [f for f in first.findings if f.rule_id == "SIGMA"]
    assert len(sig) == 6
    second = correlate(b.case.repo, sigma=FIXTURES)
    assert len([f for f in b.case.repo.list_findings() if f.rule_id == "SIGMA"]) == 6
    assert second.removed == len(first.findings)
    none = correlate(b.case.repo, sigma=None)
    assert none.sigma is None and not [f for f in none.findings if f.rule_id == "SIGMA"]
