import pytest

from atad.core.exceptions import ScopeError, ValidationError
from atad.utils.validation import (
    target_in_scope,
    validate_case_id,
    validate_target,
)


@pytest.mark.parametrize("raw,expected", [("CASE-001", "CASE-001"), (" case-042 ", "CASE-042")])
def test_case_id_ok(raw, expected):
    assert validate_case_id(raw) == expected


@pytest.mark.parametrize("raw", ["", "CASE-1", "CASE-001; rm -rf /", "../CASE-001", "CASE-ABC"])
def test_case_id_rejected(raw):
    with pytest.raises(ValidationError):
        validate_case_id(raw)


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("192.168.1.15", "ip", "192.168.1.15"),
        ("10.0.0.0/24", "cidr", "10.0.0.0/24"),
        ("192.168.1.15/24", "cidr", "192.168.1.0/24"),
        ("127.0.0.1", "ip", "127.0.0.1"),
        ("LAB-WS-01.lab.local", "hostname", "lab-ws-01.lab.local"),
    ],
)
def test_valid_targets(raw, kind, value):
    t = validate_target(raw)
    assert (t.kind, t.value, t.is_public) == (kind, value, False)


@pytest.mark.parametrize(
    "raw",
    [
        "-sV",                     # option injection
        "--script=exploit",        # option injection
        "192.168.1.15; whoami",    # shell metacharacters
        "192.168.1.15 10.0.0.1",   # whitespace
        "$(whoami)",
        "224.0.0.1",               # multicast
        "0.0.0.0",                 # unspecified
        "",
    ],
)
def test_dangerous_or_invalid_targets_rejected(raw):
    with pytest.raises(ValidationError):
        validate_target(raw)


def test_public_needs_explicit_permission():
    with pytest.raises(ScopeError):
        validate_target("8.8.8.8")
    t = validate_target("8.8.8.8", allow_public=True)
    assert t.is_public


def test_large_range_rejected():
    with pytest.raises(ScopeError):
        validate_target("10.0.0.0/16")
    assert validate_target("10.0.0.0/22").kind == "cidr"


def test_target_in_scope():
    scope = ["192.168.1.0/24", "10.0.0.5", "lab-ws-01"]
    assert target_in_scope("192.168.1.200", scope)
    assert target_in_scope("10.0.0.5", scope)
    assert not target_in_scope("10.0.0.6", scope)
    assert target_in_scope("LAB-WS-01", scope)
    assert not target_in_scope("other-host", scope)
