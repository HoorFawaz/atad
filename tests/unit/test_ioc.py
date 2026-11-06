# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import pytest

from atad.core.exceptions import ValidationError
from atad.correlation.config import CorrelationConfig, load_config
from atad.evidence.models import Confidence, Ioc
from atad.modules.ioc import parser as p

SHA256 = "a" * 64


@pytest.mark.parametrize("text,kind,value", [
    ("203.0.113.5", "ip", "203.0.113.5"),
    ("203[.]0[.]113[.]5", "ip", "203.0.113.5"),
    ("2001:db8::1", "ip", "2001:db8::1"),
    ("198.51.100.0/24", "cidr", "198.51.100.0/24"),
    ("198.51.100.7/24", "cidr", "198.51.100.0/24"),
    ("Evil.Example.", "domain", "evil.example"),
    ("evil[.]example", "domain", "evil.example"),
    ("hxxp://evil[.]example/a", "url", "http://evil.example/a"),
    ("D41D8CD98F00B204E9800998ECF8427E", "md5", "d41d8cd98f00b204e9800998ecf8427e"),
    ("a9993e364706816aba3e25717850c26c9cd0d89d", "sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (SHA256.upper(), "sha256", SHA256),
])
def test_detect_and_normalize(text, kind, value):
    r = p.parse_text(text)
    assert not r.rejected
    assert (r.iocs[0].type, r.iocs[0].value) == (kind, value)


@pytest.mark.parametrize("bad", ["1.2.3", "not an ioc", "abc123", "10.0.0.0/8", "http://", "a" * 50])
def test_rejected(bad):
    r = p.parse_text(bad)
    assert not r.iocs and len(r.rejected) == 1


def test_comments_and_blank_lines():
    r = p.parse_text("# list\n\n203.0.113.5  # c2\n  \nevil.example\n")
    assert [i.value for i in r.iocs] == ["203.0.113.5", "evil.example"]


def test_csv_with_confidence_and_type():
    text = ("value,type,confidence,description\n"
            "203.0.113.5,,high,c2 server\n"
            "evil.example,domain,low,\n"
            "1.2.3.4,ip,certain,\n"
            ",,,\n")
    r = p.parse_csv(text)
    assert [(i.value, i.confidence) for i in r.iocs] == [
        ("203.0.113.5", Confidence.HIGH), ("evil.example", Confidence.LOW)]
    assert r.iocs[0].description == "c2 server"
    assert len(r.rejected) == 1 and "confidence" in r.rejected[0][2]


def test_csv_needs_value_column():
    r = p.parse_csv("indicator\n1.2.3.4\n")
    assert not r.iocs and "value" in r.rejected[0][2]


def test_repository_dedupes(case):
    items = [Ioc(case_id=case.case.id, type="ip", value="203.0.113.5", source="a.txt")] * 2
    assert case.repo.add_iocs(items) == 1
    assert case.repo.add_iocs(items) == 0
    other = [Ioc(case_id=case.case.id, type="ip", value="203.0.113.5", source="b.txt")]
    assert case.repo.add_iocs(other) == 1
    assert len(case.repo.list_iocs()) == 2


def test_config(tmp_path):
    assert load_config(None) == CorrelationConfig()
    f = tmp_path / "c.yaml"
    f.write_text("r1_min_failures: 3\ndisabled_rules: [s2]\n")
    cfg = load_config(f)
    assert cfg.r1_min_failures == 3 and cfg.disabled_rules == ("S2",)
    f.write_text("r1_min_failure: 3\n")
    with pytest.raises(ValidationError, match="unknown"):
        load_config(f)
    f.write_text("r5_window_minutes: 0\n")
    with pytest.raises(ValidationError):
        load_config(f)
