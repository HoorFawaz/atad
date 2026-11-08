# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import os
import sys

import pytest

from atad.adapters.base import ParseContext
from atad.evidence.models import CollectionMode, EvidenceKind
from atad.modules.net import collector as nc

pytestmark = pytest.mark.skipif(sys.platform.startswith("win"), reason="fake tools are POSIX scripts")

ROUTES = ('[{"dst":"default","gateway":"10.66.1.1","dev":"eth0","protocol":"dhcp","metric":100},'
          '{"dst":"10.66.1.0/24","dev":"eth0","protocol":"kernel","prefsrc":"10.66.1.27"}]')


def _fake(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(f"#!{sys.executable}\nimport sys\n{body}\n")
    p.chmod(0o755)
    return str(p)


def _ctx():
    return ParseContext(case_id="CASE-001", host="web01", collection_mode=CollectionMode.LOCAL)


def test_routes_from_ip_json(tmp_path, monkeypatch):
    _fake(tmp_path, "ip", f"sys.stdout.write({ROUTES!r})")
    monkeypatch.setattr("atad.core.platform.current_os", lambda: "linux")
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    routes = nc.collect_routes()
    assert routes["error"] is None and len(routes["entries"]) == 2
    ev = nc.interfaces_to_evidence({"records": [], "routes": routes}, _ctx())
    assert len(ev) == 1 and ev[0].kind is EvidenceKind.HOST_INFO
    assert "default via 10.66.1.1 dev eth0" in ev[0].summary


def test_routes_skipped_off_linux(monkeypatch):
    monkeypatch.setattr("atad.core.platform.current_os", lambda: "windows")
    assert nc.collect_routes() is None


def test_dig_record_types(tmp_path, monkeypatch):
    body = ("t = sys.argv[-1]\n"
            "print({'MX': '10 mail.example.com.', 'NS': 'ns1.example.com.\\nns2.example.com.',"
            " 'TXT': '\"v=spf1 -all\"', 'CNAME': ''}[t])")
    _fake(tmp_path, "dig", body)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    rec = nc.dig_records("example.com")
    assert rec == {"MX": ["10 mail.example.com."], "NS": ["ns1.example.com.", "ns2.example.com."],
                   "TXT": ['"v=spf1 -all"']}
    cap = {"check": "dns", "query": "example.com", "type": "forward (A/AAAA)",
           "answers": ["192.0.2.10"], "error": None, "records": rec}
    e = nc.dns_to_evidence(cap, _ctx())[0]
    assert {o.value for o in e.observables} >= {"mail.example.com", "ns1.example.com"}
    assert "via dig" in e.summary


def test_no_dig_means_no_extra_records(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert nc.dig_records("example.com") is None
