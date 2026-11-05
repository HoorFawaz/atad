# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Input validation for everything the analyst types.

Nothing reaches a subprocess or the file system without passing through
one of these functions first.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from atad.core.exceptions import ScopeError, ValidationError

CASE_ID_RE = re.compile(r"^CASE-\d{3,6}$")

# RFC 1123 hostname: labels of letters, digits and hyphens, max 253 chars.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
HOSTNAME_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*\.?$")

# Default largest range in one target (/22 = 1024 addresses); --max-hosts can
# raise it up to HARD_MAX_RANGE_ADDRESSES (/16).
MAX_RANGE_ADDRESSES = 1024
HARD_MAX_RANGE_ADDRESSES = 65536


@dataclass(frozen=True)
class ValidatedTarget:
    value: str        # normalized text form
    kind: str         # ip | cidr | hostname
    is_public: bool   # True when any address is outside private/lab ranges


def validate_case_id(case_id: str) -> str:
    """Accept ``CASE-001`` style ids (case-insensitive input)."""
    value = (case_id or "").strip().upper()
    if not CASE_ID_RE.match(value):
        raise ValidationError(f"invalid case id {case_id!r} (expected e.g. CASE-001)")
    return value


def validate_evidence_path(raw: str | Path, *, must_exist: bool = True) -> "Path":
    """Validate a file or folder path given by the analyst; returns an absolute path."""
    from pathlib import Path

    text = str(raw or "").strip()
    if not text:
        raise ValidationError("path is empty")
    if "\x00" in text:
        raise ValidationError("path contains a NUL byte")
    path = Path(text).expanduser()
    try:
        path = path.absolute()
    except OSError as exc:
        raise ValidationError(f"invalid path {raw!r}: {exc}") from None
    if must_exist and not (path.exists() or path.is_symlink()):
        raise ValidationError(f"path does not exist: {path}")
    return path


def validate_source_host(raw: str) -> str:
    """Host name typed by the analyst for imported evidence (shown as declared)."""
    value = (raw or "").strip()
    if not value:
        raise ValidationError("--source-host is empty")
    if len(value) > 253 or any(ord(c) < 32 for c in value):
        raise ValidationError(f"invalid source host {raw!r}")
    return value


def _is_internal(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Private, loopback or link-local — the ranges a lab investigation uses."""
    return net.is_private or net.is_loopback or net.is_link_local


def validate_target(raw: str, *, allow_public: bool = False,
                    max_addresses: int = MAX_RANGE_ADDRESSES) -> ValidatedTarget:
    """Validate a network target: single IP, CIDR range or hostname.

    Rules:
    * Strings that could carry shell or tool options are rejected.
    * Ranges larger than ``max_addresses`` (default 1024, at most 65536) are rejected.
    * Public addresses need an explicit ``allow_public=True``.
    * Multicast, unspecified and reserved addresses are rejected.
    """
    if not 1 <= max_addresses <= HARD_MAX_RANGE_ADDRESSES:
        raise ValidationError(f"--max-hosts must be between 1 and {HARD_MAX_RANGE_ADDRESSES}")
    value = (raw or "").strip()
    if not value:
        raise ValidationError("target is empty")
    if value.startswith("-"):
        # Would be read as an option by nmap/ping.
        raise ValidationError(f"target must not start with '-': {raw!r}")
    if any(c.isspace() for c in value) or len(value) > 253:
        raise ValidationError(f"invalid target {raw!r}")

    # Single IP
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        ip = None
    if ip is not None:
        net = ipaddress.ip_network(ip)
        _reject_special(net, raw)
        public = not _is_internal(net)
        if public and not allow_public:
            raise ScopeError(f"{value} is a public address; use --allow-public only if you are authorized")
        return ValidatedTarget(str(ip), "ip", public)

    # CIDR range
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValidationError(f"invalid CIDR range {raw!r}: {exc}") from None
        _reject_special(net, raw)
        if net.num_addresses > max_addresses:
            raise ScopeError(
                f"{net} has {net.num_addresses} addresses; the limit is {max_addresses} "
                f"(raise it with --max-hosts, up to {HARD_MAX_RANGE_ADDRESSES})"
            )
        public = not _is_internal(net)
        if public and not allow_public:
            raise ScopeError(f"{net} is a public range; use --allow-public only if you are authorized")
        return ValidatedTarget(str(net), "cidr", public)

    # Hostname (resolution happens later; resolved IPs are checked again then)
    if HOSTNAME_RE.match(value):
        return ValidatedTarget(value.lower().rstrip("."), "hostname", False)

    raise ValidationError(f"invalid target {raw!r} (expected IP, CIDR or hostname)")


def _reject_special(net: ipaddress.IPv4Network | ipaddress.IPv6Network, raw: str) -> None:
    if net.is_multicast or net.is_unspecified or net.is_reserved:
        raise ValidationError(f"{raw!r} is a multicast, unspecified or reserved address")


def target_in_scope(candidate: str, scope: list[str]) -> bool:
    """True when ``candidate`` (an IP) is covered by any scope entry.

    Scope entries are normalized values from :func:`validate_target`.
    Hostname entries only match the same hostname text.
    """
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate.lower().rstrip(".") in {s.lower() for s in scope}

    for entry in scope:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue  # hostname entry
    return False
