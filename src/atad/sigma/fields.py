# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Which evidence a Sigma rule looks at, and under which field names.

| Sigma logsource                         | ATAD evidence                                        |
|-----------------------------------------|------------------------------------------------------|
| windows / process_creation              | Sysmon 1, Security 4688, running processes (psutil)  |
| windows / network_connection            | Sysmon 3, live connections (psutil)                  |
| windows / file_event                    | Sysmon 11                                            |
| windows / service: security             | Security log events                                  |
| windows / service: sysmon               | Sysmon events                                        |
| linux / process_creation                | auditd execve                                        |
| linux / network_connection              | auditd connect                                       |
| linux / service: auditd                 | auditd records (raw fields: type, a0, a1, exe, ...)  |
| linux / service: auth, sshd, syslog, sudo | auth.log / journal records                         |
| linux (no category or service)          | every Linux log record (keywords)                    |

Windows field names are the raw event fields, so Sigma rules apply as
written. Security 4688 also gets the Sysmon names (Image, ParentImage,
ProcessId) — the same mapping the SigmaHQ Windows pipelines use.
"""

from __future__ import annotations

import json
from typing import Any

from atad.evidence.models import Evidence, EvidenceKind, SourceModule
from atad.modules.logs.mapping import SECURITY, SYSMON

Event = dict[str, Any]


def _sources(e: Evidence) -> set[tuple[str, str, str]]:
    """(product, kind, name) tags; kind is 'category' or 'service'."""
    d = e.data
    ch, eid = d.get("channel"), d.get("event_id")
    tags: set[tuple[str, str, str]] = set()
    if e.source_module is SourceModule.LOG:
        if ch == SYSMON:
            tags.add(("windows", "service", "sysmon"))
            cat = {1: "process_creation", 3: "network_connection", 11: "file_event"}.get(eid)
            if cat:
                tags.add(("windows", "category", cat))
        elif ch == SECURITY:
            tags.add(("windows", "service", "security"))
            if eid == 4688:
                tags.add(("windows", "category", "process_creation"))
        elif ch == "audit":
            tags.add(("linux", "service", "auditd"))
            cat = {"execve": "process_creation", "connect": "network_connection"}.get(eid)
            if cat:
                tags.add(("linux", "category", cat))
        elif ch in ("auth", "journal"):
            tags.add(("linux", "service", "auth"))
            tags.add(("linux", "service", "syslog"))
            prog = (d.get("program") or "").lower()
            if prog.startswith("sshd"):
                tags.add(("linux", "service", "sshd"))
            if prog == "sudo":
                tags.add(("linux", "service", "sudo"))
    elif e.source_module is SourceModule.HOST and e.data.get("exe") is not None:
        product = "linux" if str(e.data.get("exe") or "").startswith("/") else "windows"
        if e.kind is EvidenceKind.PROCESS:
            tags.add((product, "category", "process_creation"))
        elif e.kind is EvidenceKind.NETWORK_CONNECTION:
            tags.add((product, "category", "network_connection"))
    return tags


def source_tags(e: Evidence) -> frozenset[tuple[str, str, str]]:
    return frozenset(_sources(e))


def applies_to_tags(logsource: dict[str, str], tags: frozenset[tuple[str, str, str]]) -> bool:
    if not tags:
        return False
    product = logsource.get("product")
    if product and not any(t[0] == product for t in tags):
        return False
    for kind in ("category", "service"):
        want = logsource.get(kind)
        if want and not any(t[1] == kind and t[2] == want for t in tags):
            return False
    return True


def applies(logsource: dict[str, str], e: Evidence) -> bool:
    return applies_to_tags(logsource, source_tags(e))


def to_event(e: Evidence) -> Event:
    """Field names a Sigma rule expects, for one evidence record."""
    d = e.data
    raw = d.get("fields") if isinstance(d.get("fields"), dict) else {}
    ev: Event = dict(raw)
    ch = d.get("channel")
    if ch in (SECURITY, SYSMON):
        ev["EventID"] = d.get("event_id")
        ev["Channel"] = ch
        ev["Provider_Name"] = d.get("provider")
        ev["Computer"] = d.get("computer")
        if ch == SECURITY and d.get("event_id") == 4688:
            ev.setdefault("Image", raw.get("NewProcessName"))
            ev.setdefault("ParentImage", raw.get("ParentProcessName"))
            ev.setdefault("ProcessId", raw.get("NewProcessId"))
            ev.setdefault("User", d.get("user"))
    elif ch == "audit":
        types = raw.get("types") or []
        ev["type"] = types
        if d.get("event_id") == "execve":
            for i, a in enumerate(raw.get("argv") or []):
                ev[f"a{i}"] = a
            ev["Image"] = d.get("image")
            ev["CommandLine"] = d.get("command_line")
            ev["CurrentDirectory"] = raw.get("cwd")
            ev["ProcessId"] = d.get("pid")
            ev["ParentProcessId"] = d.get("ppid")
        else:
            ev["Image"] = d.get("image")
            ev["DestinationIp"] = d.get("destination_ip")
            ev["DestinationPort"] = d.get("destination_port")
            ev["Initiated"] = "true"
    elif ch in ("auth", "journal"):
        ev["message"] = d.get("message")
        ev["program"] = d.get("program")
    elif e.source_module is SourceModule.HOST:
        if e.kind is EvidenceKind.PROCESS:
            ev.update(Image=d.get("exe"), CommandLine=d.get("cmdline"), User=d.get("user"),
                      ProcessId=d.get("pid"), ParentProcessId=d.get("ppid"))
        elif e.kind is EvidenceKind.NETWORK_CONNECTION:
            ev.update(Image=d.get("exe"), DestinationIp=d.get("remote_ip"),
                      DestinationPort=d.get("remote_port"), SourceIp=d.get("local_ip"),
                      SourcePort=d.get("local_port"), Protocol=d.get("protocol"), Initiated="true")
    ev = {k: v for k, v in ev.items() if v is not None}
    ev["_keywords_text"] = " ".join(
        [str(d.get("message") or ""), e.summary]
        + [json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else str(v)
           for k, v in ev.items() if not k.startswith("_")])
    return ev
