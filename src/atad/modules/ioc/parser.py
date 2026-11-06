# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Reading indicator lists (IOCs).

Supported formats:

* **Plain text** — one indicator per line; the type is detected
  (IPv4/IPv6, CIDR range, domain, URL, MD5, SHA-1, SHA-256). ``#`` starts a
  comment. Defanged indicators (``hxxp://``, ``evil[.]com``, ``10[.]0[.]0[.]1``)
  are restored.
* **CSV** — header with at least ``value``; optional ``type``,
  ``confidence`` (low/medium/high) and ``description``.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from atad.evidence.models import Confidence, ObservableType, normalize_observable

SUPPORTED_TYPES = ("ip", "cidr", "domain", "url", "md5", "sha1", "sha256")

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$")
# A domain must end in a label that is not only digits (rules out "1.2.3")
_TLD_OK = re.compile(r"[A-Za-z]")

MAX_CIDR_ADDRESSES = 65536


@dataclass
class ParsedIoc:
    type: str
    value: str
    confidence: Confidence | None = None
    description: str = ""


@dataclass
class ParseReport:
    iocs: list[ParsedIoc] = field(default_factory=list)
    rejected: list[tuple[int, str, str]] = field(default_factory=list)  # (line, text, reason)


def refang(text: str) -> str:
    t = text.strip()
    t = re.sub(r"^hxxp", "http", t, flags=re.IGNORECASE)
    t = re.sub(r"^fxp", "ftp", t, flags=re.IGNORECASE)
    for a in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        t = t.replace(a, ".")
    t = t.replace("[:]", ":").replace("[://]", "://")
    return t


def detect_type(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    if "://" in v:
        return "url"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return "cidr"
        except ValueError:
            return None
    if _HEX.match(v):
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(v))
    if _DOMAIN.match(v) and _TLD_OK.search(v.rstrip(".").rsplit(".", 1)[-1]):
        return "domain"
    return None


def normalize(kind: str, value: str) -> str:
    """Canonical form, so indicators compare equal to collected observables."""
    v = value.strip()
    if kind == "cidr":
        net = ipaddress.ip_network(v, strict=False)
        if net.num_addresses > MAX_CIDR_ADDRESSES:
            raise ValueError(f"range larger than {MAX_CIDR_ADDRESSES} addresses")
        return str(net)
    if kind == "url":
        parts = urlsplit(v)
        if not parts.scheme or not parts.hostname:
            raise ValueError("URL without scheme or host")
        return v
    return normalize_observable(ObservableType(kind), v)


def url_host(url: str) -> str | None:
    host = urlsplit(url).hostname
    return host.lower().rstrip(".") if host else None


def _one(raw: str, kind: str | None, line_no: int, report: ParseReport,
         confidence: Confidence | None = None, description: str = "") -> None:
    text = refang(raw)
    kind = (kind or "").strip().lower() or detect_type(text)
    if kind not in SUPPORTED_TYPES:
        report.rejected.append((line_no, raw.strip(), "unknown indicator type"))
        return
    try:
        value = normalize(kind, text)
    except ValueError as exc:
        report.rejected.append((line_no, raw.strip(), str(exc)))
        return
    report.iocs.append(ParsedIoc(kind, value, confidence, description))


def parse_text(text: str) -> ParseReport:
    report = ParseReport()
    for n, line in enumerate(text.splitlines(), start=1):
        content = line.split("#", 1)[0].strip()
        if content:
            _one(content, None, n, report)
    return report


def parse_csv(text: str) -> ParseReport:
    report = ParseReport()
    reader = csv.DictReader(io.StringIO(text))
    fields = {f.strip().lower(): f for f in (reader.fieldnames or [])}
    if "value" not in fields:
        report.rejected.append((1, ",".join(reader.fieldnames or []), "CSV needs a 'value' column"))
        return report
    for n, row in enumerate(reader, start=2):
        get = lambda k: (row.get(fields[k]) or "").strip() if k in fields else ""  # noqa: E731
        value = get("value")
        if not value or value.startswith("#"):
            continue
        conf_text = get("confidence").lower()
        confidence = None
        if conf_text:
            try:
                confidence = Confidence(conf_text)
            except ValueError:
                report.rejected.append((n, value, f"confidence must be low, medium or high"))
                continue
        _one(value, get("type"), n, report, confidence, get("description"))
    return report


def parse_file(path: Path) -> ParseReport:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if path.suffix.lower() == ".csv":
        return parse_csv(text)
    return parse_text(text)
