"""Detection specs for every tool atad knows about (MVP: Windows first)."""

from __future__ import annotations

from atad.adapters.base import ExternalTool, PythonLibrary, ToolAdapter, ToolInfo
from atad.core.execution import resolve_executable, run_command

WIN = frozenset({"windows"})
ALL = frozenset({"windows", "linux"})

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


# ----------------------------------------------------------- Python libraries


class Psutil(PythonLibrary):
    name = "psutil"
    purpose = "processes, connections, system info"
    module = "psutil"
    distribution = "psutil"
    required = True


class PythonEvtx(PythonLibrary):
    name = "python-evtx"
    purpose = "read Windows .evtx log files"
    module = "Evtx"
    distribution = "python-evtx"
    required = True


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


class OsQuery(ExternalTool):
    name = "osquery"
    purpose = "endpoint queries (post-MVP)"
    executables = ("osqueryi",)
    version_args = ("--version",)
    version_pattern = r"osqueryi? version (\S+)"


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


ALL_TOOLS: tuple[type[ToolAdapter], ...] = (
    Psutil, PythonEvtx, Jinja2, YaraPython,
    Ping, Wevtutil,
    Nmap, Sysmon, OsQuery,
)
