# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Reading Windows .evtx files and turning each record into a plain dict.

Two layers, so parsing can be tested without real .evtx files:

* :func:`iter_evtx_xml` — reads an .evtx file (Rust `evtx`, or python-evtx) and yields
  the XML of each record (with a limit).
* :func:`parse_event_xml` — turns one record's XML into a dict.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

DEFAULT_MAX_EVENTS = 100_000

_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_system_time(value: str) -> datetime | None:
    """Parse an EVTX ``SystemTime``. EVTX stores UTC, so a missing zone means UTC.

    Handles both python-evtx's ``2016-07-08 18:12:51.681641+00:00`` and the
    Windows form ``2016-07-08T18:12:51.6816410Z`` (7 fraction digits).
    """
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    text = _FRACTION.sub(r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _find(parent: ET.Element, name: str) -> ET.Element | None:
    el = parent.find(NS + name)
    return el if el is not None else parent.find(name)


def parse_event_xml(xml: str | bytes) -> dict[str, Any] | None:
    """Return a dict for one event, or None when the XML is not an event."""
    if isinstance(xml, str) and xml.lstrip().startswith("<?xml"):
        xml = xml.encode("utf-8")  # ElementTree refuses str with an encoding declaration
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    system = _find(root, "System")
    if system is None:
        return None

    def text(name: str) -> str | None:
        el = _find(system, name)
        return el.text.strip() if el is not None and el.text else None

    provider = _find(system, "Provider")
    time_el = _find(system, "TimeCreated")
    try:
        event_id = int(text("EventID") or "")
    except ValueError:
        return None
    record_id = text("EventRecordID")

    data: dict[str, str] = {}
    event_data = _find(root, "EventData")
    if event_data is not None:
        for i, d in enumerate(list(event_data)):
            name = d.get("Name") or f"Data{i}"
            data[name] = (d.text or "").strip()
    user_data = _find(root, "UserData")
    if user_data is not None:
        for el in user_data.iter():
            if el is not user_data and el.text and el.text.strip() and not list(el):
                data.setdefault(el.tag.split("}")[-1], el.text.strip())

    return {
        "event_id": event_id,
        "record_id": int(record_id) if record_id and record_id.isdigit() else None,
        "channel": text("Channel"),
        "provider": provider.get("Name") if provider is not None else None,
        "computer": text("Computer"),
        "time": time_el.get("SystemTime") if time_el is not None else None,
        "data": data,
    }


@dataclass
class ReadStats:
    records_read: int = 0
    record_errors: int = 0
    truncated: bool = False
    errors: list[str] = field(default_factory=list)
    engine: str | None = None          # which parser read the file


def available_engine() -> str | None:
    """'evtx' (Rust, fast — the parser Chainsaw uses) or 'python-evtx' (pure Python)."""
    import importlib.util

    if importlib.util.find_spec("evtx") is not None:
        return "evtx"
    if importlib.util.find_spec("Evtx") is not None:
        return "python-evtx"
    return None


def _note_error(stats: ReadStats, exc: Exception) -> None:
    stats.record_errors += 1
    if len(stats.errors) < 20:
        stats.errors.append(f"record {stats.records_read}: {exc}")


def iter_evtx_xml(path: Path, stats: ReadStats, max_events: int = DEFAULT_MAX_EVENTS) -> Iterator[str]:
    """Yield the XML of each record. Broken records are counted, not fatal.

    Uses the Rust ``evtx`` parser when installed (hundreds of times faster),
    otherwise python-evtx.
    """
    engine = available_engine()
    stats.engine = engine
    if engine == "evtx":
        from evtx import PyEvtxParser

        records = PyEvtxParser(str(path)).records()
        while True:
            if stats.records_read >= max_events:
                stats.truncated = True
                return
            try:
                rec = next(records)
            except StopIteration:
                return
            except Exception as exc:  # noqa: BLE001 - parsers raise many types on damaged records
                stats.records_read += 1
                _note_error(stats, exc)
                continue
            stats.records_read += 1
            yield rec["data"]
        return

    if engine is None:
        raise RuntimeError("no EVTX parser installed (pip install evtx)")

    import Evtx.Evtx as evtx  # python-evtx fallback

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            if stats.records_read >= max_events:
                stats.truncated = True
                return
            stats.records_read += 1
            try:
                yield record.xml()
            except Exception as exc:  # noqa: BLE001 - corrupted record: keep going
                _note_error(stats, exc)


def is_evtx(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == b"ElfFile\x00"
    except OSError:
        return False
