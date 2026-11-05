# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Maps the supported Windows events to normalized evidence.

Supported subset (MVP) — anything else is counted but not stored:

| Channel  | Event | Meaning                 | Evidence kind        |
|----------|-------|-------------------------|----------------------|
| Security | 4624  | successful logon        | logon                |
| Security | 4625  | failed logon            | logon                |
| Security | 4688  | process created         | process              |
| Security | 4720  | user account created    | log_event            |
| Sysmon   | 1     | process created         | process              |
| Sysmon   | 3     | network connection      | network_connection   |
| Sysmon   | 11    | file created            | log_event            |
"""

from __future__ import annotations

import ipaddress
from pathlib import PureWindowsPath
from typing import Any

from atad.adapters.base import ParseContext
from atad.evidence.models import Evidence, EvidenceKind, Observable, SourceModule
from atad.modules.logs.evtx_reader import parse_system_time

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"

SUPPORTED: dict[str, set[int]] = {
    SECURITY: {4624, 4625, 4688, 4720},
    SYSMON: {1, 3, 11},
}

# Short names used by `atad log search --keyword ...`
KEYWORDS: dict[str, set[tuple[str, int]]] = {
    "failed_login": {(SECURITY, 4625)},
    "successful_login": {(SECURITY, 4624)},
    "process_created": {(SECURITY, 4688), (SYSMON, 1)},
    "user_created": {(SECURITY, 4720)},
    "network_connection": {(SYSMON, 3)},
    "file_created": {(SYSMON, 11)},
}

LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
    "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def is_supported(event: dict[str, Any]) -> bool:
    return event.get("event_id") in SUPPORTED.get(event.get("channel") or "", set())


# ---------------------------------------------------------------- helpers


def _clean(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    return None if v in ("", "-", "N/A") else v


def _ip_obs(value: str | None) -> list[Observable]:
    v = _clean(value)
    if not v:
        return []
    v = v.removeprefix("::ffff:")
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return []
    return [Observable(type="ip", value=v)]


def _pid(value: str | None) -> int | None:
    v = _clean(value)
    if not v:
        return None
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None


def _user(domain: str | None, name: str | None) -> str | None:
    name, domain = _clean(name), _clean(domain)
    if not name:
        return None
    return f"{domain}\\{name}" if domain else name


def _hashes(value: str | None) -> dict[str, str]:
    """Sysmon 'SHA1=..,MD5=..,SHA256=..' → {'sha256': .., 'md5': ..}."""
    out: dict[str, str] = {}
    for part in (value or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


def _name(path: str | None) -> str:
    return PureWindowsPath(path).name if path else "?"


def _obs(*items: tuple[str, Any]) -> list[Observable]:
    out: list[Observable] = []
    for kind, value in items:
        if value is None or value == "":
            continue
        try:
            out.append(Observable(type=kind, value=str(value)))
        except ValueError:
            continue  # skip malformed values instead of failing the whole event
    return out


# ---------------------------------------------------------------- mapping


def event_to_evidence(event: dict[str, Any], ctx: ParseContext) -> Evidence | None:
    """Return evidence for a supported event, else None."""
    if not is_supported(event):
        return None
    channel, eid, d = event["channel"], event["event_id"], event["data"]
    short = "Security" if channel == SECURITY else "Sysmon"
    base = dict(
        case_id=ctx.case_id,
        source_module=SourceModule.LOG,
        source_tool=ctx.tool or "evtx",
        tool_version=ctx.tool_version,
        collection_mode=ctx.collection_mode,
        host=ctx.host,
        host_declared=ctx.host_declared,
        execution_id=ctx.execution_id,
        raw_ref=ctx.raw_ref,
        raw_sha256=ctx.raw_sha256,
        simulated=ctx.simulated,
        event_time=parse_system_time(event.get("time") or ""),
    )
    data = {
        "channel": channel,
        "event_id": eid,
        "record_id": event.get("record_id"),
        "provider": event.get("provider"),
        "computer": event.get("computer"),
        "fields": d,
    }
    host_obs = _obs(("hostname", _clean(event.get("computer"))))

    if channel == SECURITY and eid in (4624, 4625):
        ok = eid == 4624
        user = _user(d.get("TargetDomainName"), d.get("TargetUserName"))
        ltype = d.get("LogonType", "")
        src = _clean(d.get("IpAddress"))
        data.update(outcome="success" if ok else "failure",
                    user=user, logon_type=LOGON_TYPES.get(ltype, ltype), source_ip=src)
        summary = (f"{'Successful' if ok else 'Failed'} logon for {user or '?'}"
                   f" ({LOGON_TYPES.get(ltype, 'type ' + ltype)})"
                   + (f" from {src}" if src else ""))
        obs = _obs(("user", user), ("hostname", _clean(d.get("WorkstationName"))),
                   ("path", _clean(d.get("ProcessName"))))
        return Evidence(**base, kind=EvidenceKind.LOGON, summary=summary, data=data,
                        observables=obs + _ip_obs(src) + host_obs)

    if channel == SECURITY and eid == 4688:
        image = _clean(d.get("NewProcessName"))
        pid = _pid(d.get("NewProcessId"))
        user = _user(d.get("SubjectDomainName"), d.get("SubjectUserName"))
        data.update(image=image, pid=pid, parent_image=_clean(d.get("ParentProcessName")),
                    command_line=_clean(d.get("CommandLine")), user=user)
        return Evidence(**base, kind=EvidenceKind.PROCESS,
                        summary=f"Process created: {_name(image)} (pid {pid}) by {user or '?'}",
                        data=data,
                        observables=_obs(("path", image), ("pid", pid), ("user", user)) + host_obs)

    if channel == SECURITY and eid == 4720:
        new_user = _user(d.get("TargetDomainName"), d.get("TargetUserName"))
        by = _user(d.get("SubjectDomainName"), d.get("SubjectUserName"))
        data.update(new_user=new_user, created_by=by)
        return Evidence(**base, kind=EvidenceKind.LOG_EVENT,
                        summary=f"User account created: {new_user or '?'} by {by or '?'}",
                        data=data, observables=_obs(("user", new_user), ("user", by)) + host_obs)

    if channel == SYSMON and eid == 1:
        image = _clean(d.get("Image"))
        pid = _pid(d.get("ProcessId"))
        h = _hashes(d.get("Hashes"))
        user = _clean(d.get("User"))
        data.update(image=image, pid=pid, process_guid=_clean(d.get("ProcessGuid")),
                    parent_image=_clean(d.get("ParentImage")),
                    parent_process_guid=_clean(d.get("ParentProcessGuid")),
                    command_line=_clean(d.get("CommandLine")), user=user, hashes=h)
        return Evidence(**base, kind=EvidenceKind.PROCESS,
                        summary=f"Process created: {_name(image)} (pid {pid}) by {user or '?'}",
                        data=data,
                        observables=_obs(("path", image), ("pid", pid),
                                         ("process_guid", _clean(d.get("ProcessGuid"))),
                                         ("user", user), ("sha256", h.get("sha256")),
                                         ("md5", h.get("md5"))) + host_obs)

    if channel == SYSMON and eid == 3:
        image = _clean(d.get("Image"))
        dst, dport = _clean(d.get("DestinationIp")), _clean(d.get("DestinationPort"))
        dhost = _clean(d.get("DestinationHostname"))
        data.update(image=image, pid=_pid(d.get("ProcessId")),
                    process_guid=_clean(d.get("ProcessGuid")),
                    protocol=_clean(d.get("Protocol")), initiated=_clean(d.get("Initiated")),
                    source_ip=_clean(d.get("SourceIp")), source_port=_clean(d.get("SourcePort")),
                    destination_ip=dst, destination_port=dport, destination_host=dhost,
                    user=_clean(d.get("User")))
        return Evidence(**base, kind=EvidenceKind.NETWORK_CONNECTION,
                        summary=f"{_name(image)} connected to {dhost or dst}:{dport}",
                        data=data,
                        observables=_obs(("path", image), ("pid", data["pid"]),
                                         ("process_guid", data["process_guid"]),
                                         ("domain", dhost), ("user", data["user"]))
                        + _ip_obs(dst) + host_obs)

    if channel == SYSMON and eid == 11:
        image, target = _clean(d.get("Image")), _clean(d.get("TargetFilename"))
        data.update(image=image, target_file=target, pid=_pid(d.get("ProcessId")),
                    process_guid=_clean(d.get("ProcessGuid")))
        return Evidence(**base, kind=EvidenceKind.LOG_EVENT,
                        summary=f"{_name(image)} created file {_name(target)}",
                        data=data,
                        observables=_obs(("path", image), ("path", target), ("pid", data["pid"]),
                                         ("process_guid", data["process_guid"])) + host_obs)
    return None  # pragma: no cover - guarded by is_supported
