# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Linux persistence locations (read-only).

| Location                                   | type             | MITRE ATT&CK |
|--------------------------------------------|------------------|--------------|
| systemd units in /etc and user unit dirs   | systemd          | T1543.002    |
| /etc/crontab, /etc/cron.d, user crontabs   | cron             | T1053.003    |
| /etc/rc.local                              | rc_local         | T1037.004    |
| shell start-up files (only risky lines)    | shell_profile    | T1546.004    |
| ~/.ssh/authorized_keys                     | authorized_keys  | T1098.004    |

Vendor units in /usr/lib are not listed unless enabled from /etc. Shell
start-up files hold ordinary settings, so only lines that download and run
code, open a reverse shell, or start a program from a user-writable folder
are recorded.
"""

from __future__ import annotations

import os
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

USER_WRITABLE = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
_RISKY = [
    (re.compile(r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"),
     "downloads and runs code (curl/wget piped to a shell)"),
    (re.compile(r"(?i)base64\s+(-d|--decode)[^|]*\|\s*(ba|z|da|k)?sh\b"), "decodes and runs hidden code"),
    (re.compile(r"/dev/(tcp|udp)/"), "opens a network shell (/dev/tcp)"),
    (re.compile(r"(?i)\b(nc|ncat|netcat)\b.*\s-(e|c)\s"), "netcat with -e/-c (reverse shell)"),
    (re.compile(r"(?i)\bpython\d?\s+-c\s+.*\bsocket\b"), "python one-liner opening a socket"),
]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def reasons_for(command: str | None, executable: str | None) -> list[str]:
    out = []
    exe = (executable or "").lower()
    if exe and any(exe.startswith(d) or d in exe for d in USER_WRITABLE):
        out.append("starts from a user-writable folder")
    for rx, why in _RISKY:
        if command and rx.search(command):
            out.append(why)
    return out


def executable_of(command: str | None) -> str | None:
    if not command:
        return None
    c = command.strip().lstrip("-@+!")              # systemd prefixes like -/usr/bin/x
    try:
        parts = shlex.split(c)
    except ValueError:
        parts = c.split()
    while parts and re.match(r"^\w+=", parts[0]):    # VAR=value cmd
        parts = parts[1:]
    if parts and parts[0] in ("sudo", "nohup", "exec", "env", "/usr/bin/env", "sh", "bash", "/bin/sh", "/bin/bash") \
            and len(parts) > 1 and not parts[1].startswith("-"):
        return parts[1]
    return parts[0] if parts else None


def _item(kind: str, location: str, name: str, command: str | None, path: Path | None,
          **extra: Any) -> dict[str, Any]:
    exe = extra.pop("executable", None) or executable_of(command)
    item = {"location": location, "type": kind, "name": name, "command": command, "executable": exe,
            **extra}
    if path is not None:
        try:
            item["modified_utc"] = _iso(path.stat().st_mtime)
        except OSError:
            pass
    item["suspicious_reasons"] = reasons_for(command, exe)
    return item


def _homes(root: Path) -> list[tuple[str, Path]]:
    out = [("root", root / "root")]
    home = root / "home"
    if home.is_dir():
        out += [(p.name, p) for p in sorted(home.iterdir()) if p.is_dir()]
    return out


def _read(path: Path, errors: list[str]) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        errors.append(f"{path}: {exc.strerror or exc}")
        return None


# ----------------------------------------------------------------- systemd


def _exec_start(text: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(r"(?m)^\s*ExecStart\s*=\s*(.+)$", text) if m.group(1).strip()]


def _systemd(root: Path, errors: list[str]) -> list[dict]:
    items = []
    seen: set[Path] = set()
    dirs = [root / "etc/systemd/system"]
    dirs += [h / ".config/systemd/user" for _, h in _homes(root)]
    for d in dirs:
        if not d.is_dir():
            continue
        candidates = sorted(d.glob("*.service")) + sorted(d.glob("*.wants/*.service"))
        for unit in candidates:
            target = unit
            try:
                if unit.is_symlink():
                    link = os.readlink(unit)
                    target = (root / link.lstrip("/")) if link.startswith("/") else unit.parent / link
            except OSError:
                pass
            key = target.resolve() if target.exists() else target
            if key in seen or not target.is_file():
                continue
            seen.add(key)
            text = _read(target, errors)
            if text is None:
                continue
            for cmd in _exec_start(text) or [None]:
                items.append(_item("systemd", str(unit.parent).replace(str(root), "/", 1).replace("//", "/"),
                                   unit.name, cmd, target,
                                   enabled=".wants" in unit.parent.name or None))
    return items


# --------------------------------------------------------------------- cron

_CRON_SYSTEM = re.compile(r"^\s*(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(\S+)\s+(.+)$")
_CRON_USER = re.compile(r"^\s*(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$")


def _cron_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#") and not re.match(r"^\s*\w+\s*=", ln)]


def _cron(root: Path, errors: list[str]) -> list[dict]:
    items = []
    system = [root / "etc/crontab"] + (sorted((root / "etc/cron.d").iterdir())
                                        if (root / "etc/cron.d").is_dir() else [])
    for f in system:
        if not f.is_file():
            continue
        text = _read(f, errors)
        for ln in _cron_lines(text or ""):
            m = _CRON_SYSTEM.match(ln)
            if m:
                items.append(_item("cron", str(f).replace(str(root), "/", 1).replace("//", "/"),
                                   f"{f.name}: {m.group(1)}", m.group(3).strip(), f,
                                   schedule=m.group(1), user=m.group(2)))
    for spool in (root / "var/spool/cron/crontabs", root / "var/spool/cron"):
        if not spool.is_dir():
            continue
        for f in sorted(p for p in spool.iterdir() if p.is_file()):
            text = _read(f, errors)
            for ln in _cron_lines(text or ""):
                m = _CRON_USER.match(ln)
                if m:
                    items.append(_item("cron", str(f).replace(str(root), "/", 1).replace("//", "/"),
                                       f"{f.name}: {m.group(1)}", m.group(2).strip(), f,
                                       schedule=m.group(1), user=f.name))
    return items


# ------------------------------------------------------------ rc.local, profiles


def _rc_local(root: Path, errors: list[str]) -> list[dict]:
    f = root / "etc/rc.local"
    if not f.is_file():
        return []
    items = []
    for ln in (_read(f, errors) or "").splitlines():
        s = ln.strip()
        if s and not s.startswith("#") and s not in ("exit 0",) and not s.startswith("#!"):
            items.append(_item("rc_local", "/etc/rc.local", "rc.local", s, f))
    return items


def _profiles(root: Path, errors: list[str]) -> list[dict]:
    files = [root / "etc/profile", root / "etc/bash.bashrc", root / "etc/bashrc"]
    if (root / "etc/profile.d").is_dir():
        files += sorted((root / "etc/profile.d").glob("*.sh"))
    for _, h in _homes(root):
        files += [h / n for n in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login")]
    items = []
    for f in files:
        if not f.is_file():
            continue
        for ln in (_read(f, errors) or "").splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            exe = executable_of(s)
            if reasons_for(s, exe):
                items.append(_item("shell_profile", str(f).replace(str(root), "/", 1).replace("//", "/"),
                                   f.name, s, f))
    return items


def _authorized_keys(root: Path, errors: list[str]) -> list[dict]:
    items = []
    for user, h in _homes(root):
        f = h / ".ssh/authorized_keys"
        if not f.is_file():
            continue
        for ln in (_read(f, errors) or "").splitlines():
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            m = re.search(r"(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s+(\S+)(?:\s+(.*))?$", s)
            if not m:
                continue
            options = s[:m.start()].strip() or None
            forced = re.search(r'command="([^"]*)"', options or "")
            item = _item("authorized_keys", str(f).replace(str(root), "/", 1).replace("//", "/"),
                         (m.group(3) or "(no comment)").strip(), forced.group(1) if forced else None, f,
                         user=user, key_type=m.group(1), key_end=m.group(2)[-12:], options=options,
                         executable=executable_of(forced.group(1)) if forced else None)
            items.append(item)
    return items


def collect_startup_linux(root: Path = Path("/")) -> dict[str, Any]:
    errors: list[str] = []
    items = (_systemd(root, errors) + _cron(root, errors) + _rc_local(root, errors)
             + _profiles(root, errors) + _authorized_keys(root, errors))
    return {"check": "startup", "count": len(items), "errors": errors, "records": items}
