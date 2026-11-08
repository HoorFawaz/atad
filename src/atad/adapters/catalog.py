# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Detection specs for every tool atad knows about (Windows and Linux)."""

from __future__ import annotations

from atad.adapters.base import ExternalTool, PythonLibrary, ToolAdapter, ToolInfo
from atad.core.execution import resolve_executable, run_command

WIN = frozenset({"windows"})
LNX = frozenset({"linux"})
ALL = frozenset({"windows", "linux"})

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


# ----------------------------------------------------------- Python libraries


class Psutil(PythonLibrary):
    name = "psutil"
    purpose = "processes, connections, system info"
    module = "psutil"
    distribution = "psutil"
    required = True


class EvtxRust(PythonLibrary):
    name = "evtx"
    purpose = "fast .evtx reader (Rust, same parser as Chainsaw)"
    module = "evtx"
    distribution = "evtx"
    required = True


class PythonEvtx(PythonLibrary):
    name = "python-evtx"
    purpose = "slow fallback .evtx reader"
    module = "Evtx"
    distribution = "python-evtx"


class Jinja2(PythonLibrary):
    name = "jinja2"
    purpose = "HTML reports"
    module = "jinja2"
    distribution = "jinja2"
    required = True


class YaraPython(PythonLibrary):
    name = "yara"
    purpose = "scan files with YARA rules"
    module = "yara"
    distribution = "yara-python"


# --------------------------------------------------------------- OS built-ins


class Ping(ExternalTool):
    name = "ping"
    purpose = "connectivity test"
    executables = ("ping",)
    version_args = ()
    required = True


class Wevtutil(ExternalTool):
    name = "wevtutil"
    purpose = "export Windows event logs"
    executables = ("wevtutil",)
    version_args = ()
    supported_os = WIN
    required = True


# -------------------------------------------------------- optional externals


class Nmap(ExternalTool):
    name = "nmap"
    purpose = "host discovery, ports, services"
    executables = ("nmap",)
    version_args = ("--version",)
    version_pattern = r"Nmap version (\S+)"


class Sysmon(ToolAdapter):
    """Sysmon is detected by its event log channel, which atad reads."""

    name = "sysmon"
    purpose = "process / network / file telemetry"
    supported_os = WIN

    def _detect(self) -> ToolInfo:
        wevtutil = resolve_executable("wevtutil")
        if wevtutil is None:
            return self._info(False, reason="wevtutil not found, cannot check Sysmon")
        res = run_command([wevtutil, "gl", SYSMON_CHANNEL], timeout=15, max_output=64 * 1024)
        if res.ok:
            return self._info(True, path=SYSMON_CHANNEL)
        return self._info(False, reason="Sysmon log channel not found (Sysmon not installed?)")


# ------------------------------------------------------------------- Linux


class Journalctl(ExternalTool):
    name = "journalctl"
    purpose = "systemd journal (sshd, sudo, useradd, services)"
    executables = ("journalctl",)
    version_args = ("--version",)
    version_pattern = r"systemd (\d+)"
    supported_os = LNX


class _LogFile(ToolAdapter):
    paths: tuple[str, ...] = ()
    supported_os = LNX

    def _detect(self) -> ToolInfo:
        import os

        for p in self.paths:
            if os.path.isfile(p):
                if os.access(p, os.R_OK):
                    return self._info(True, path=p)
                return self._info(False, path=p, reason=f"{p} exists but needs root to read")
        return self._info(False, reason=f"not found ({', '.join(self.paths)})")


class AuthLog(_LogFile):
    name = "auth-log"
    purpose = "SSH logins, sudo, useradd (auth.log / secure)"
    paths = ("/var/log/auth.log", "/var/log/secure")


class AuditLog(_LogFile):
    name = "auditd"
    purpose = "process execution and connections (audit.log)"
    paths = ("/var/log/audit/audit.log",)


class IpRoute(ExternalTool):
    name = "ip"
    purpose = "routing table (ip -j route)"
    executables = ("ip",)
    version_args = ("-V",)
    version_pattern = r"iproute2-(\S+)"
    supported_os = LNX


class Dig(ExternalTool):
    name = "dig"
    purpose = "DNS record types (MX, NS, TXT, CNAME)"
    executables = ("dig",)
    version_args = ("-v",)
    version_pattern = r"DiG (\S+)"


ALL_TOOLS: tuple[type[ToolAdapter], ...] = (
    Psutil, EvtxRust, PythonEvtx, Jinja2, YaraPython,
    Ping, Wevtutil,
    Nmap, Sysmon,
    Journalctl, AuthLog, AuditLog, IpRoute, Dig,
)
