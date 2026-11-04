import shutil
import socket
from pathlib import Path

import pytest

from atad.adapters.base import ParseContext
from atad.core.exceptions import ScopeError, ValidationError
from atad.evidence.models import CollectionMode, EvidenceKind, ExecutionStatus, Target
from atad.modules.net import collector as nc
from atad.modules.net import runner as nr
from atad.utils.validation import validate_target

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def ctx(**kw):
    base = dict(case_id="CASE-001", host="192.168.1.15", collection_mode=CollectionMode.NETWORK,
                simulated=True)
    base.update(kw)
    return ParseContext(**base)


# ----------------------------------------------------------------- ping parse

WIN_OK = (b"Pinging 192.168.1.15 with 32 bytes of data:\r\n"
          b"Reply from 192.168.1.15: bytes=32 time=1ms TTL=128\r\n"
          b"Reply from 192.168.1.15: bytes=32 time<1ms TTL=128\r\n")
WIN_UNREACHABLE = (b"Pinging 192.168.1.99 with 32 bytes of data:\r\n"
                   b"Reply from 192.168.1.1: Destination host unreachable.\r\n")
LINUX_OK = b"64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.032 ms\n"


def test_ping_windows_reply():
    r = nc.parse_ping(WIN_OK, 0, "192.168.1.15")
    assert r["reachable"] and r["ttl"] == 128 and r["replies"] == 2 and r["avg_ms"] == 1.0
    assert r["replies_under_1ms"] == 1


def test_ping_windows_unreachable_exit_zero_is_not_reachable():
    r = nc.parse_ping(WIN_UNREACHABLE, 0, "192.168.1.99")
    assert not r["reachable"] and r["replies"] == 0


def test_ping_linux():
    assert nc.parse_ping(LINUX_OK, 0, "127.0.0.1")["ttl"] == 64


def test_ping_args():
    assert nc.build_ping_args("ping", "10.0.0.5", "windows") == ["ping", "-n", "4", "-w", "1000", "10.0.0.5"]
    assert nc.build_ping_args("ping", "10.0.0.5", "linux") == ["ping", "-c", "4", "-W", "1", "10.0.0.5"]


def test_ping_evidence_wording():
    e = nc.ping_to_evidence(nc.parse_ping(b"", 1, "10.0.0.5"), ctx())[0]
    assert "did not reply" in e.summary and "firewall" in e.summary


# ----------------------------------------------------------------------- nmap


def test_nmap_args_safe_profiles():
    a = nc.build_nmap_args("nmap", ["192.168.1.15"], "standard")
    assert a[:2] == ["nmap", "-sT"] and "-Pn" in a and a[-3:] == ["-oX", "-", "192.168.1.15"]
    assert not any(x.startswith("--script") or x in ("-sC", "-A", "-O") for x in a)
    q = nc.build_nmap_args("nmap", ["192.168.1.0/24"], "quick", single_host=False)
    assert "-F" in q and "-Pn" not in q


def test_nmap_ports_replace_profile_ports():
    a = nc.build_nmap_args("nmap", ["10.0.0.5"], "standard", ports="22, 80,8000-8100")
    assert "--top-ports" not in a and a[a.index("-p") + 1] == "22,80,8000-8100"


@pytest.mark.parametrize("bad", ["22;id", "0", "70000", "80-22", "-sV", "22,,80", "a"])
def test_bad_ports(bad):
    with pytest.raises(ValidationError):
        nc.validate_ports(bad)


def test_bad_profile_and_target():
    with pytest.raises(ValidationError):
        nc.build_nmap_args("nmap", ["10.0.0.5"], "aggressive")
    with pytest.raises(ValidationError):
        nc.build_nmap_args("nmap", ["-iL"], "quick")


def test_parse_real_nmap_output():
    p = nc.parse_nmap_xml((FIX / "nmap_single_host.xml").read_bytes())
    h = p["hosts"][0]
    assert h["ip"] == "127.0.0.1" and h["state"] == "up"
    assert [x["port"] for x in h["open_ports"]] == [8088]
    assert h["open_ports"][0]["product"] == "SimpleHTTPServer"


def test_parse_range_and_evidence():
    p = nc.parse_nmap_xml((FIX / "nmap_range.xml").read_bytes())
    assert p["elapsed_s"] == 12.34 and len(p["hosts"]) == 3
    ev = nc.nmap_to_evidence(p, ctx(host="192.168.1.8/29"))
    hosts = [e for e in ev if e.kind is EvidenceKind.HOST_INFO]
    ports = [e for e in ev if e.kind is EvidenceKind.OPEN_PORT]
    assert {e.host for e in hosts} == {"192.168.1.15", "192.168.1.10"}   # down host ignored
    assert len(ports) == 4                                               # closed 8080 ignored
    rdp = next(e for e in ports if e.data["port"] == 3389)
    assert rdp.summary == "192.168.1.15:3389/tcp open — Microsoft Terminal Services"
    assert {o.value for o in rdp.observables} == {"192.168.1.15", "lab-ws-01.lab.local"}


def test_parse_rejects_non_nmap():
    with pytest.raises(Exception):
        nc.parse_nmap_xml(b"<html/>")


# ------------------------------------------------------------------------ dns


def test_dns_forward_and_reverse(monkeypatch):
    monkeypatch.setattr(nc.socket, "getaddrinfo",
                        lambda name, port: [(0, 0, 0, "", ("192.168.1.15", 0))])
    monkeypatch.setattr(nc.socket, "gethostbyaddr", lambda ip: ("lab-ws-01.lab.local", [], [ip]))
    f = nc.collect_dns("lab-ws-01.lab.local")
    assert f["answers"] == ["192.168.1.15"] and f["error"] is None
    r = nc.collect_dns("192.168.1.15")
    assert r["answers"] == ["lab-ws-01.lab.local"]
    e = nc.dns_to_evidence(f, ctx())[0]
    assert {o.type.value for o in e.observables} == {"domain", "ip"}


def test_dns_no_record(monkeypatch):
    def boom(*a):
        raise socket.herror(1, "Unknown host")
    monkeypatch.setattr(nc.socket, "gethostbyaddr", boom)
    r = nc.collect_dns("192.168.1.77")
    assert r["answers"] == [] and "no record" in r["error"]


# ---------------------------------------------------------------------- scope


def _scope(*vals, public=False):
    out = []
    for v in vals:
        vt = validate_target(v, allow_public=public)
        out.append(Target(case_id="CASE-001", value=vt.value, kind=vt.kind, is_public=vt.is_public))
    return out


def test_scope_ip_and_cidr():
    scope = _scope("192.168.1.0/24")
    assert nr.scan_targets(validate_target("192.168.1.15"), scope) == ["192.168.1.15"]
    assert nr.scan_targets(validate_target("192.168.1.0/25"), scope) == ["192.168.1.0/25"]
    with pytest.raises(ScopeError):
        nr.scan_targets(validate_target("192.168.2.1"), scope)
    with pytest.raises(ScopeError):
        nr.scan_targets(validate_target("192.168.0.0/23"), scope)  # bigger than scope


def test_scope_hostname_must_be_listed_and_resolve_inside(monkeypatch):
    scope = _scope("lab-ws-01.lab.local")
    monkeypatch.setattr(nc, "resolve_name", lambda n: ["192.168.1.15"])
    assert nr.scan_targets(validate_target("lab-ws-01.lab.local"), scope) == ["192.168.1.15"]
    with pytest.raises(ScopeError):
        nr.scan_targets(validate_target("other.lab.local"), scope)
    # name that points outside → refused
    monkeypatch.setattr(nc, "resolve_name", lambda n: ["93.184.216.34"])
    with pytest.raises(ScopeError, match="public"):
        nr.scan_targets(validate_target("lab-ws-01.lab.local"), scope)


# --------------------------------------------------------------------- runner


def test_run_net_refuses_out_of_scope_before_running(case):
    with pytest.raises(ScopeError):
        nr.run_net(case, ["ping", "scan"], target="10.1.1.1", auto_scope=False)
    assert case.repo.list_executions() == []


def test_internal_target_recorded_in_scope(case, monkeypatch):
    monkeypatch.setattr(nr.Ping, "detect", lambda self: nr.Ping()._info(False, reason="test"))
    r = nr.run_net(case, ["ping"], target="10.1.1.1")
    assert r.scope_added and r.scope_added.value == "10.1.1.1"
    assert case.repo.list_targets()[0].note == "added automatically by atad net"
    r2 = nr.run_net(case, ["ping"], target="10.1.1.1")
    assert r2.scope_added is None                      # already covered


def test_public_target_still_needs_permission(case):
    with pytest.raises(ScopeError):
        nr.run_net(case, ["ping"], target="8.8.8.8")
    assert case.repo.list_targets() == []


def test_dns_on_public_ip_needs_no_scope(case, monkeypatch):
    monkeypatch.setattr(nc.socket, "gethostbyaddr", lambda ip: ("dns.google", [], [ip]))
    r = nr.run_net(case, ["dns"], target="8.8.8.8")
    assert r.outcome("dns").execution.status is ExecutionStatus.SUCCESS
    assert case.repo.list_targets() == []              # nothing touched, nothing authorized


def test_max_hosts(case):
    with pytest.raises(ScopeError, match="max-hosts"):
        nr.run_net(case, ["scan"], target="10.0.0.0/20")
    with pytest.raises(ValidationError):
        validate_target("10.0.0.0/8", max_addresses=10_000_000)
    assert validate_target("10.0.0.0/20", max_addresses=4096).kind == "cidr"


def test_run_net_without_target(case):
    r = nr.run_net(case, ["interfaces", "ping"], excluded=["scan", "dns"])
    assert r.outcome("interfaces").execution.status is ExecutionStatus.SUCCESS
    assert r.outcome("ping").execution.error == "no --target given"
    assert {o.check for o in r.outcomes} == {"interfaces", "ping", "scan", "dns"}


def test_range_skips_single_host_checks(case, manager, monkeypatch):
    manager.add_scope(case.case.id, "192.168.1.0/29")
    monkeypatch.setattr(nr.Nmap, "detect", lambda self: nr.Nmap()._info(False, reason="test"))
    r = nr.run_net(case, ["ping", "scan", "dns"], target="192.168.1.0/29")
    assert "single host" in r.outcome("ping").execution.error
    assert "single host" in r.outcome("dns").execution.error
    assert r.outcome("scan").execution.status is ExecutionStatus.UNAVAILABLE


needs_tools = pytest.mark.skipif(not (shutil.which("nmap") and shutil.which("ping")),
                                 reason="nmap and ping not installed")


@needs_tools
def test_real_ping_and_scan_on_localhost(case, manager):
    manager.add_scope(case.case.id, "127.0.0.1")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        r = nr.run_net(case, ["ping", "scan"], target="127.0.0.1", ports=str(port), profile="quick")
    finally:
        srv.close()
    assert r.outcome("ping").execution.status is ExecutionStatus.SUCCESS
    assert r.outcome("ping").capture["reachable"]
    scan = r.outcome("scan")
    assert scan.execution.status is ExecutionStatus.SUCCESS
    assert [e.data["port"] for e in scan.evidence if e.kind is EvidenceKind.OPEN_PORT] == [port]
    assert (case.path / scan.execution.raw_ref).read_bytes().startswith(b"<?xml")
