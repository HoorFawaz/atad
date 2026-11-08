# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Linux log parsers: auth.log / secure (syslog lines), systemd journal JSON, auditd.

Supported subset (M9) — anything else is counted but not stored:

| Source        | Event                         | id               | Evidence kind      |
|---------------|-------------------------------|------------------|--------------------|
| auth / journal| SSH login accepted            | ssh_accepted     | logon              |
| auth / journal| SSH password failed           | ssh_failed       | logon              |
| auth / journal| sudo command                  | sudo             | log_event          |
| auth / journal| sudo wrong password(s)        | sudo_failed      | log_event          |
| auth / journal| new user (useradd)            | user_created     | log_event          |
| journal       | systemd started a service     | service_started  | log_event          |
| audit         | program executed (execve)     | execve           | process            |
| audit         | outbound connection (connect) | connect          | network_connection |

Time: journal and audit records carry exact UTC times. Classic syslog lines
("Nov  7 10:01:02") carry neither year nor time zone; the year is taken from
the file's modification time and the zone must be given (live collection uses
this machine's zone, import uses --timezone, UTC by default). Every record says
which basis was used, so a reader can see an assumed time.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import Any

from atad.adapters.base import ParseContext
from atad.evidence.models import Evidence, EvidenceKind, Observable, SourceModule

AUTH, JOURNAL, AUDIT = "auth", "journal", "audit"

SUPPORTED_LINUX = {
    AUTH: {"ssh_accepted", "ssh_failed", "sudo", "sudo_failed", "user_created"},
    JOURNAL: {"ssh_accepted", "ssh_failed", "sudo", "sudo_failed", "user_created", "service_started"},
    AUDIT: {"execve", "connect"},
}

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# ------------------------------------------------------------------ syslog lines

_ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
_BSD_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")

_SSH_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SUDO_CMD = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<note>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ; (?:.*? ; )?COMMAND=(?P<cmd>.*)$")
_SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?")
_USERADD = re.compile(r"^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+)")
_SERVICE = re.compile(r"^Started (?P<unit>\S+\.service)")


@dataclass
class LinuxRecord:
    source: str                         # auth | journal | audit
    event: str                          # e.g. ssh_failed
    time: datetime | None
    time_basis: str                     # "exact" or a description of the assumption
    host: str | None
    program: str | None
    pid: int | None
    message: str
    fields: dict[str, Any] = field(default_factory=dict)


def parse_message(program: str | None, message: str) -> tuple[str, dict[str, Any]] | None:
    """Recognize the supported messages of sshd, sudo, useradd and systemd."""
    prog = (program or "").lower()
    if prog.startswith("sshd"):
        m = _SSH_FAILED.match(message)
        if m:
            return "ssh_failed", {"user": m["user"], "source_ip": m["ip"], "port": int(m["port"]),
                                  "method": m["method"], "invalid_user": bool(m["invalid"])}
        m = _SSH_ACCEPTED.match(message)
        if m:
            return "ssh_accepted", {"user": m["user"], "source_ip": m["ip"],
                                    "port": int(m["port"]), "method": m["method"]}
    elif prog == "sudo":
        m = _SUDO_FAIL.match(message)          # checked first: it also has COMMAND=
        if m:
            return "sudo_failed", {"user": m["user"], "attempts": int(m["n"])}
        m = _SUDO_CMD.match(message)
        if m:
            return "sudo", {"user": m["user"], "target_user": m["target"], "tty": m["tty"],
                            "cwd": m["pwd"], "command_line": m["cmd"].strip(),
                            "note": (m["note"] or "").strip() or None}
    elif prog == "useradd":
        m = _USERADD.match(message)
        if m:
            return "user_created", {"new_user": m["name"].strip(), "uid": int(m["uid"])}
    elif prog == "systemd":
        m = _SERVICE.match(message)
        if m:
            return "service_started", {"unit": m["unit"]}
    return None


def _bsd_time(mon: str, day: str, hms: str, year: int, tz: tzinfo) -> datetime | None:
    try:
        h, mi, s = (int(x) for x in hms.split(":"))
        return datetime(year, MONTHS[mon], int(day), h, mi, s, tzinfo=tz).astimezone(UTC)
    except (KeyError, ValueError):
        return None


@dataclass
class SyslogStats:
    lines: int = 0
    unparsed: int = 0
    unsupported: int = 0
    assumed_times: int = 0


def iter_syslog(text: str, *, file_mtime: datetime, tz: tzinfo, tz_label: str,
                stats: SyslogStats | None = None) -> Iterator[LinuxRecord]:
    """auth.log / secure / syslog lines → supported records.

    Lines without a year get one from the file's modification time; if that
    puts a line in the future (December lines read in January), the year
    before is used.
    """
    stats = stats or SyslogStats()
    limit = file_mtime + timedelta(days=1)
    for line in text.splitlines():
        if not line.strip():
            continue
        stats.lines += 1
        m = _ISO_LINE.match(line)
        if m:
            ts = m["ts"].replace("Z", "+00:00")
            if re.search(r"[+-]\d{4}$", ts):
                ts = ts[:-2] + ":" + ts[-2:]
            try:
                when, basis = datetime.fromisoformat(ts).astimezone(UTC), "exact"
            except ValueError:
                stats.unparsed += 1
                continue
        else:
            m = _BSD_LINE.match(line)
            if not m:
                stats.unparsed += 1
                continue
            when = _bsd_time(m["mon"], m["day"], m["time"], file_mtime.year, tz)
            if when and when > limit:
                when = _bsd_time(m["mon"], m["day"], m["time"], file_mtime.year - 1, tz)
            basis = f"year from file date, time zone {tz_label} (syslog line has neither)"
            stats.assumed_times += 1
        parsed = parse_message(m["prog"], m["msg"])
        if parsed is None:
            stats.unsupported += 1
            continue
        event, fields = parsed
        yield LinuxRecord(AUTH, event, when, basis, m["host"], m["prog"],
                          int(m["pid"]) if m["pid"] else None, m["msg"], fields)


# ------------------------------------------------------------------ journal JSON


def _journal_message(value: Any) -> str:
    if isinstance(value, list):            # non-UTF-8 messages are byte arrays
        return bytes(v & 0xFF for v in value).decode("utf-8", "replace")
    return str(value or "")


def iter_journal(text: str, stats: SyslogStats | None = None) -> Iterator[LinuxRecord]:
    """`journalctl -o json` output (one JSON object per line)."""
    stats = stats or SyslogStats()
    for line in text.splitlines():
        if not line.strip():
            continue
        stats.lines += 1
        try:
            obj = json.loads(line)
            when = datetime.fromtimestamp(int(obj["__REALTIME_TIMESTAMP"]) / 1_000_000,
                                          tz=UTC)
        except (ValueError, KeyError, TypeError):
            stats.unparsed += 1
            continue
        program = obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM")
        message = _journal_message(obj.get("MESSAGE"))
        parsed = parse_message(program, message)
        if parsed is None:
            stats.unsupported += 1
            continue
        event, fields = parsed
        pid = obj.get("_PID") or obj.get("SYSLOG_PID")
        yield LinuxRecord(JOURNAL, event, when, "exact", obj.get("_HOSTNAME"), program,
                          int(pid) if str(pid or "").isdigit() else None, message,
                          {**fields, "unit": fields.get("unit") or obj.get("_SYSTEMD_UNIT")})


# ------------------------------------------------------------------ auditd

_AUDIT_LINE = re.compile(r"^type=(?P<type>\S+) msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\):\s?(?P<rest>.*)$")
_KV = re.compile(r'(\S+?)=("(?:[^"\\]|\\.)*"|\S+)')
# connect() syscall numbers by audit arch
_CONNECT = {"c000003e": "42", "c00000b7": "203"}           # x86_64, aarch64
_HEX = re.compile(r"^[0-9A-Fa-f]+$")


def _kv(rest: str) -> dict[str, str]:
    out = {}
    for k, v in _KV.findall(rest.split("\x1d", maxsplit=1)[0]):
        out[k] = v[1:-1] if v.startswith('"') else v
    return out


def _decode_arg(raw: str, quoted: bool) -> str:
    """auditd writes an argument as hex when it contains spaces or quotes."""
    if not quoted and _HEX.match(raw) and len(raw) % 2 == 0:
        try:
            return bytes.fromhex(raw).decode("utf-8", "replace")
        except ValueError:
            return raw
    return raw


def _sockaddr(hexstr: str) -> tuple[str, int] | None:
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        return None
    family = int.from_bytes(b[0:2], "little")
    if family == 2 and len(b) >= 8:                          # AF_INET
        return str(ipaddress.IPv4Address(b[4:8])), int.from_bytes(b[2:4], "big")
    if family == 10 and len(b) >= 24:                        # AF_INET6
        return str(ipaddress.IPv6Address(b[8:24])), int.from_bytes(b[2:4], "big")
    return None


def iter_audit(text: str, stats: SyslogStats | None = None,
               host: str | None = None) -> Iterator[LinuxRecord]:
    """audit.log: group records of one event (same serial), keep execve and connect."""
    stats = stats or SyslogStats()
    events: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        stats.lines += 1
        m = _AUDIT_LINE.match(line.strip())
        if not m:
            stats.unparsed += 1
            continue
        key = f"{m['ts']}:{m['serial']}"
        if key not in events:
            events[key] = {"ts": m["ts"], "serial": m["serial"], "records": {}}
            order.append(key)
        rec_type, rest = m["type"], m["rest"]
        if rec_type == "EXECVE":
            raw = dict(_KV.findall(rest))
            argc = int(raw.get("argc", "0") or 0)
            args = []
            for i in range(argc):
                v = raw.get(f"a{i}")
                if v is None:
                    break
                quoted = v.startswith('"')
                args.append(_decode_arg(v[1:-1] if quoted else v, quoted))
            events[key]["argv"] = args
            events[key]["records"].setdefault("EXECVE", _kv(rest))
        else:
            events[key]["records"].setdefault(rec_type, _kv(rest))

    for key in order:
        ev = events[key]
        recs = ev["records"]
        sc = recs.get("SYSCALL", {})
        when = datetime.fromtimestamp(float(ev["ts"]), tz=UTC)
        fields = {"serial": ev["serial"], "types": sorted(recs)}
        for r in recs.values():
            for k, v in r.items():
                fields.setdefault(k, v)
        base = {"image": sc.get("exe"), "pid": int(sc["pid"]) if sc.get("pid", "").isdigit() else None,
                    "ppid": int(sc["ppid"]) if sc.get("ppid", "").isdigit() else None,
                    "uid": sc.get("uid"), "auid": sc.get("auid"), "comm": sc.get("comm"),
                    "success": sc.get("success"), "key": None if sc.get("key") in (None, "(null)") else sc.get("key")}
        if "EXECVE" in recs:
            argv = ev.get("argv", [])
            yield LinuxRecord(AUDIT, "execve", when, "exact", host, sc.get("comm"), base["pid"],
                              " ".join(argv), {**fields, **base, "argv": argv,
                                               "command_line": " ".join(argv),
                                               "cwd": recs.get("CWD", {}).get("cwd")})
            continue
        if "SOCKADDR" in recs and sc.get("syscall") == _CONNECT.get(sc.get("arch", "")):
            addr = _sockaddr(recs["SOCKADDR"].get("saddr", ""))
            if addr:
                yield LinuxRecord(AUDIT, "connect", when, "exact", host, sc.get("comm"), base["pid"],
                                  f"connect to {addr[0]}:{addr[1]}",
                                  {**fields, **base, "destination_ip": addr[0],
                                   "destination_port": addr[1]})
                continue
        stats.unsupported += 1


# ------------------------------------------------------------------ detection


def detect_format(path: Path) -> str | None:
    """evtx | journal | audit | syslog | None (by content, not by name)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if head.startswith(b"ElfFile\x00"):
        return "evtx"
    text = head.decode("utf-8", "replace").lstrip("\ufeff").lstrip()
    if text.startswith("{") and '"__REALTIME_TIMESTAMP"' in text:
        return "journal"
    first = text.splitlines()[0] if text else ""
    if _AUDIT_LINE.match(first):
        return "audit"
    if _ISO_LINE.match(first) or _BSD_LINE.match(first):
        return "syslog"
    return None


# ------------------------------------------------------------------ evidence

_LABEL = {AUTH: "auth log", JOURNAL: "journal", AUDIT: "auditd"}


def _obs(*items: tuple[str, Any]) -> list[Observable]:
    out = []
    for kind, value in items:
        if value in (None, ""):
            continue
        try:
            out.append(Observable(type=kind, value=str(value)))
        except ValueError:
            continue
    return out


def _clean_ip(v: str | None) -> str | None:
    if not v:
        return None
    v = v.removeprefix("::ffff:")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def record_to_evidence(rec: LinuxRecord, ctx: ParseContext) -> Evidence:
    f = rec.fields
    data = {"channel": rec.source, "event_id": rec.event, "program": rec.program, "pid": rec.pid,
            "message": rec.message, "computer": rec.host, "time_basis": rec.time_basis,
            "fields": f}
    base = {"case_id": ctx.case_id, "source_module": SourceModule.LOG, "source_tool": ctx.tool or rec.source,
                "tool_version": ctx.tool_version, "collection_mode": ctx.collection_mode, "host": ctx.host,
                "host_declared": ctx.host_declared, "execution_id": ctx.execution_id, "raw_ref": ctx.raw_ref,
                "raw_sha256": ctx.raw_sha256, "simulated": ctx.simulated, "event_time": rec.time}
    host_obs = _obs(("hostname", rec.host))
    src = _LABEL[rec.source]

    if rec.event in ("ssh_failed", "ssh_accepted"):
        ok = rec.event == "ssh_accepted"
        ip = _clean_ip(f.get("source_ip"))
        data.update(outcome="success" if ok else "failure", user=f["user"], source_ip=ip,
                    logon_type=f"SSH ({f['method']})")
        who = f"invalid user {f['user']}" if f.get("invalid_user") else f["user"]
        return Evidence(**base, kind=EvidenceKind.LOGON,
                        summary=f"{'Successful' if ok else 'Failed'} SSH logon for {who} from {ip or f.get('source_ip')} ({src})",
                        data=data, observables=_obs(("user", f["user"]), ("ip", ip)) + host_obs)
    if rec.event == "sudo":
        data.update(user=f["user"], command_line=f["command_line"])
        return Evidence(**base, kind=EvidenceKind.LOG_EVENT,
                        summary=f"sudo by {f['user']} as {f['target_user']}: {f['command_line'][:120]}",
                        data=data, observables=_obs(("user", f["user"])) + host_obs)
    if rec.event == "sudo_failed":
        data.update(user=f["user"])
        return Evidence(**base, kind=EvidenceKind.LOG_EVENT,
                        summary=f"sudo: {f['attempts']} wrong password attempt(s) by {f['user']}",
                        data=data, observables=_obs(("user", f["user"])) + host_obs)
    if rec.event == "user_created":
        data.update(new_user=f["new_user"])
        return Evidence(**base, kind=EvidenceKind.LOG_EVENT,
                        summary=f"User account created: {f['new_user']} (uid {f['uid']})",
                        data=data, observables=_obs(("user", f["new_user"])) + host_obs)
    if rec.event == "service_started":
        data.update(unit=f.get("unit"))
        return Evidence(**base, kind=EvidenceKind.LOG_EVENT,
                        summary=f"Service started: {f.get('unit')}", data=data, observables=host_obs)
    if rec.event == "execve":
        data.update(image=f.get("image"), pid=f.get("pid"), ppid=f.get("ppid"),
                    command_line=f.get("command_line"), uid=f.get("uid"), auid=f.get("auid"))
        name = Path(f.get("image") or rec.program or "?").name
        return Evidence(**base, kind=EvidenceKind.PROCESS,
                        summary=f"Process executed: {name} (pid {f.get('pid')}, uid {f.get('uid')}): "
                                f"{(f.get('command_line') or '')[:120]}",
                        data=data, observables=_obs(("path", f.get("image")), ("pid", f.get("pid"))) + host_obs)
    if rec.event == "connect":
        data.update(image=f.get("image"), pid=f.get("pid"), destination_ip=f["destination_ip"],
                    destination_port=f["destination_port"])
        name = Path(f.get("image") or rec.program or "?").name
        return Evidence(**base, kind=EvidenceKind.NETWORK_CONNECTION,
                        summary=f"{name} connected to {f['destination_ip']}:{f['destination_port']} (auditd)",
                        data=data,
                        observables=_obs(("path", f.get("image")), ("pid", f.get("pid")),
                                         ("ip", _clean_ip(f["destination_ip"]))) + host_obs)
    raise ValueError(f"unsupported Linux event {rec.event}")  # pragma: no cover
