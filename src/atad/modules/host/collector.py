# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Endpoint collection with psutil (and the Windows registry for startup items).

Runs on the machine being investigated (local mode). Read-only: nothing is
stopped, killed, changed or removed. Fields Windows refuses to give
(AccessDenied) are kept as ``None`` and counted, never guessed.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

from atad.adapters.base import ParseContext
from atad.evidence.models import Evidence, EvidenceKind, Observable, SourceModule
from atad.modules.common import base_fields

MAX_HASH_BYTES = 100 * 1024 * 1024

# Folders normal users can write to: programs running from here deserve a look.
_USER_WRITABLE = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\", "\\users\\public\\",
    "\\appdata\\roaming\\", "/tmp/", "/dev/shm/", "/var/tmp/",
)
_ENCODED_PS = re.compile(r"(?i)powershell.*\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s")


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _sha256(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# --------------------------------------------------------------------- info


def collect_info() -> dict[str, Any]:
    import psutil

    vm = psutil.virtual_memory()
    return {
        "check": "info",
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "boot_time_utc": _iso(psutil.boot_time()),
        "cpu_count": psutil.cpu_count(),
        "memory_total_bytes": vm.total,
        "collected_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
    }


def info_to_evidence(cap: dict, ctx: ParseContext) -> list[Evidence]:
    return [Evidence(
        **base_fields(ctx, SourceModule.HOST, "psutil"),
        kind=EvidenceKind.HOST_INFO,
        event_time=datetime.fromisoformat(cap["boot_time_utc"]) if cap.get("boot_time_utc") else None,
        summary=f"{cap['hostname']}: {cap['os']} {cap['os_release']} ({cap['architecture']}), "
                f"last boot {cap.get('boot_time_utc') or '?'}",
        data=cap,
        observables=[Observable(type="hostname", value=cap["hostname"])],
    )]


# ---------------------------------------------------------------- processes


def process_flags(exe: str | None, cmdline: str | None, exe_exists: bool | None) -> list[str]:
    reasons = []
    low = (exe or "").lower()
    win = low.replace("/", "\\")
    if exe and any(d in low or d in win for d in _USER_WRITABLE):
        reasons.append("runs from a user-writable folder")
    if cmdline and _ENCODED_PS.search(cmdline + " "):
        reasons.append("PowerShell with an encoded command")
    if exe and exe_exists is False:
        reasons.append("program file no longer exists on disk")
    return reasons


def collect_processes(hash_executables: bool = True) -> dict[str, Any]:
    import psutil

    attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "status"]
    records, denied = [], 0
    hashes: dict[str, str | None] = {}
    for p in psutil.process_iter(attrs=attrs, ad_value=None):
        info = p.info
        exe = info.get("exe") or None
        cmd = " ".join(info["cmdline"]) if info.get("cmdline") else None
        if exe is None or info.get("username") is None:
            denied += 1
        exists = os.path.exists(exe) if exe else None
        sha = None
        if hash_executables and exe and exists:
            if exe not in hashes:
                hashes[exe] = _sha256(exe)
            sha = hashes[exe]
        records.append({
            "pid": info["pid"], "ppid": info.get("ppid"), "name": info.get("name"),
            "exe": exe, "cmdline": cmd, "user": info.get("username"),
            "started_utc": _iso(info.get("create_time")), "status": info.get("status"),
            "sha256": sha, "suspicious_reasons": process_flags(exe, cmd, exists),
        })
    # parent names help the analyst read the tree
    names = {r["pid"]: r["name"] for r in records}
    for r in records:
        r["parent_name"] = names.get(r["ppid"])
    return {"check": "processes", "count": len(records), "access_denied": denied,
            "unique_executables_hashed": sum(1 for v in hashes.values() if v), "records": records}


def processes_to_evidence(cap: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for r in cap["records"]:
        obs = [Observable(type="pid", value=str(r["pid"]))]
        if r.get("exe"):
            obs.append(Observable(type="path", value=r["exe"]))
        if r.get("user"):
            obs.append(Observable(type="user", value=r["user"]))
        if r.get("sha256"):
            obs.append(Observable(type="sha256", value=r["sha256"]))
        flag = " — SUSPICIOUS: " + "; ".join(r["suspicious_reasons"]) if r["suspicious_reasons"] else ""
        out.append(Evidence(
            **base_fields(ctx, SourceModule.HOST, "psutil"),
            kind=EvidenceKind.PROCESS,
            event_time=datetime.fromisoformat(r["started_utc"]) if r.get("started_utc") else None,
            summary=f"Running: {r.get('name') or '?'} (pid {r['pid']}, user {r.get('user') or '?'}){flag}",
            data=r, observables=obs,
        ))
    return out


# -------------------------------------------------------------- connections


def collect_connections() -> dict[str, Any]:
    import psutil

    procs: dict[int, tuple[str | None, str | None]] = {}
    for p in psutil.process_iter(attrs=["pid", "name", "exe"], ad_value=None):
        procs[p.info["pid"]] = (p.info.get("name"), p.info.get("exe"))
    records = []
    for c in psutil.net_connections(kind="inet"):
        name, exe = procs.get(c.pid, (None, None)) if c.pid else (None, None)
        records.append({
            "protocol": "tcp" if c.type == socket.SOCK_STREAM else "udp",
            "family": "ipv6" if c.family == socket.AF_INET6 else "ipv4",
            "local_ip": c.laddr.ip if c.laddr else None,
            "local_port": c.laddr.port if c.laddr else None,
            "remote_ip": c.raddr.ip if c.raddr else None,
            "remote_port": c.raddr.port if c.raddr else None,
            "state": c.status, "pid": c.pid, "process": name, "exe": exe,
        })
    return {"check": "connections", "count": len(records), "records": records}


def connections_to_evidence(cap: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for r in cap["records"]:
        obs = []
        if r.get("pid"):
            obs.append(Observable(type="pid", value=str(r["pid"])))
        if r.get("exe"):
            obs.append(Observable(type="path", value=r["exe"]))
        listening = r["state"] == "LISTEN" or (r["protocol"] == "udp" and not r.get("remote_ip"))
        proc = r.get("process") or "?"
        if listening:
            kind = EvidenceKind.OPEN_PORT
            summary = f"Listening {r['protocol'].upper()} {r['local_ip']}:{r['local_port']} ({proc})"
        else:
            kind = EvidenceKind.NETWORK_CONNECTION
            if r.get("remote_ip"):
                obs.append(Observable(type="ip", value=r["remote_ip"]))
            summary = (f"{proc} {r['local_ip']}:{r['local_port']} -> "
                       f"{r.get('remote_ip')}:{r.get('remote_port')} {r['state']}")
        out.append(Evidence(**base_fields(ctx, SourceModule.HOST, "psutil"),
                            kind=kind, summary=summary, data=r, observables=obs))
    return out


# -------------------------------------------------------------------- users


def collect_users() -> dict[str, Any]:
    import psutil

    records = [{"user": u.name, "terminal": u.terminal, "from_host": u.host or None,
                "started_utc": _iso(u.started), "pid": getattr(u, "pid", None)}
               for u in psutil.users()]
    return {"check": "users", "count": len(records), "records": records}


def users_to_evidence(cap: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for r in cap["records"]:
        obs = [Observable(type="user", value=r["user"])]
        src = r.get("from_host")
        if src:
            try:
                obs.append(Observable(type="ip", value=src))
            except ValueError:
                obs.append(Observable(type="hostname", value=src))
        out.append(Evidence(
            **base_fields(ctx, SourceModule.HOST, "psutil"), kind=EvidenceKind.USER_SESSION,
            event_time=datetime.fromisoformat(r["started_utc"]) if r.get("started_utc") else None,
            summary=f"Logged-in session: {r['user']}" + (f" from {src}" if src else "")
                    + (f" on {r['terminal']}" if r.get("terminal") else ""),
            data=r, observables=obs,
        ))
    return out


# ------------------------------------------------------------------ startup

RUN_KEYS = [
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def executable_from_command(command: str | None) -> str | None:
    """Program path from a command line such as ``"C:\\a b\\x.exe" -arg``."""
    if not command:
        return None
    c = os.path.expandvars(command.strip())
    if c.startswith('"'):
        end = c.find('"', 1)
        return c[1:end] if end > 1 else None
    m = re.match(r"(?i)^(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|com|scr))(\s|,|$)", c)
    if m:
        return m.group(1)
    return c.split()[0] if c.split() else None


def _registry_items() -> tuple[list[dict], list[str]]:
    import winreg  # Windows only

    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    items, errors = [], []
    for hive, key in RUN_KEYS:
        try:
            with winreg.OpenKey(hives[hive], key, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    items.append({"location": f"{hive}\\{key}", "type": "registry_run",
                                  "name": name, "command": str(value),
                                  "executable": executable_from_command(str(value))})
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{hive}\\{key}: {exc}")
    return items, errors


def _startup_folder_items() -> list[dict]:
    folders = []
    if os.environ.get("APPDATA"):
        folders.append(Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
    if os.environ.get("PROGRAMDATA"):
        folders.append(Path(os.environ["PROGRAMDATA"]) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    items = []
    for f in folders:
        if f.is_dir():
            for p in sorted(f.iterdir()):
                if p.name.lower() == "desktop.ini":
                    continue
                items.append({"location": str(f), "type": "startup_folder", "name": p.name,
                              "command": str(p), "executable": str(p),
                              "modified_utc": _iso(p.stat().st_mtime)})
    return items


def _service_items() -> tuple[list[dict], list[str]]:
    import psutil

    items, errors = [], []
    for s in psutil.win_service_iter():  # type: ignore[attr-defined]
        try:
            d = s.as_dict()
        except Exception as exc:
            errors.append(f"service {getattr(s, '_name', '?')}: {exc}")
            continue
        if d.get("start_type") != "automatic":
            continue
        items.append({"location": "services", "type": "service", "name": d.get("name"),
                      "display_name": d.get("display_name"), "command": d.get("binpath"),
                      "executable": executable_from_command(d.get("binpath")),
                      "user": d.get("username"), "status": d.get("status")})
    return items, errors


def collect_startup() -> dict[str, Any]:
    """Windows persistence locations: Run keys, Startup folders, auto-start services."""
    reg, reg_err = _registry_items()
    svc, svc_err = _service_items()
    items = reg + _startup_folder_items() + svc
    for it in items:
        exe = it.get("executable") or ""
        it["suspicious_reasons"] = (["starts from a user-writable folder"]
                                    if any(d in exe.lower().replace("/", "\\") for d in _USER_WRITABLE)
                                    else [])
    return {"check": "startup", "count": len(items), "errors": reg_err + svc_err, "records": items}


def startup_to_evidence(cap: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for r in cap["records"]:
        obs = []
        if r.get("executable"):
            try:
                obs.append(Observable(type="path", value=r["executable"]))
            except ValueError:
                pass
        flag = " — SUSPICIOUS: " + "; ".join(r["suspicious_reasons"]) if r["suspicious_reasons"] else ""
        label = {"registry_run": "Run key", "startup_folder": "Startup folder",
                 "service": "Auto-start service"}[r["type"]]
        out.append(Evidence(
            **base_fields(ctx, SourceModule.HOST, "winreg/psutil"),
            kind=EvidenceKind.PERSISTENCE,
            summary=f"{label}: {r['name']} -> {PureWindowsPath(r.get('executable') or '?').name}{flag}",
            data=r, observables=obs,
        ))
    return out
