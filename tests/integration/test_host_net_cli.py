# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from typer.testing import CliRunner

from atad.cli.app import app

runner = CliRunner()


def _run(home, *args):
    return runner.invoke(app, ["--home", str(home), *args])


def test_host_cli(tmp_path):
    r = _run(tmp_path / "c", "host", "--only", "info,users")
    assert r.exit_code == 0, r.output
    assert "Created CASE-001" in r.output and "skipped (your choice)" in r.output


def test_host_single_check(tmp_path):
    r = _run(tmp_path / "c", "host", "processes")
    assert r.exit_code == 0 and "processes" in r.output


def test_net_auto_case_adds_scope(tmp_path):
    home = tmp_path / "c"
    r = _run(home, "net", "--target", "127.0.0.1", "--only", "ping")
    assert r.exit_code == 0, r.output
    assert "scope: 127.0.0.1 authorized for CASE-001" in r.output
    r = _run(home, "scope", "list", "--case", "CASE-001")
    assert "added automatically by atad net" in r.output


def test_net_public_target_refused_and_no_case_created(tmp_path):
    home = tmp_path / "c"
    r = _run(home, "net", "--target", "8.8.8.8")
    assert r.exit_code == 2 and "public" in r.output
    assert "No cases yet" in _run(home, "case", "list").output


def test_net_existing_case_records_internal_target(tmp_path):
    home = tmp_path / "c"
    _run(home, "case", "new", "--name", "x")
    r = _run(home, "net", "ping", "--target", "127.0.0.1", "--case", "CASE-001")
    assert r.exit_code == 0 and "authorized for CASE-001 (recorded)" in r.output
    assert "127.0.0.1" in _run(home, "scope", "list", "--case", "CASE-001").output


def test_net_dns_public_ok_without_scope(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("dns.google", [], [ip]))
    r = _run(tmp_path / "c", "net", "dns", "--target", "8.8.8.8")
    assert r.exit_code == 0 and "dns.google" in r.output and "scope:" not in r.output


def test_net_interfaces_only(tmp_path):
    r = _run(tmp_path / "c", "net", "interfaces")
    assert r.exit_code == 0 and "Interface" in r.output


def test_bad_ports_rejected(tmp_path):
    r = _run(tmp_path / "c", "net", "scan", "--target", "127.0.0.1", "--ports", "22;id")
    assert r.exit_code == 2


def test_bad_ports_rejected_without_nmap(tmp_path, monkeypatch):
    # GitHub's test machines have no Nmap: the port list must still be checked first.
    from atad.adapters.base import ToolInfo
    from atad.adapters.catalog import Nmap
    monkeypatch.setattr(Nmap, "detect", lambda self: ToolInfo(name="nmap", available=False, reason="test"))
    home = tmp_path / "c"
    r = _run(home, "net", "scan", "--target", "127.0.0.1", "--ports", "22;id")
    assert r.exit_code == 2 and "invalid port list" in r.output
    assert "No cases yet" in _run(home, "case", "list").output
