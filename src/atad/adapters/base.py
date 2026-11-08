# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Tool adapter interface.

Every tool atad knows about is described by an adapter. In this milestone
adapters only *detect* tools; later milestones add the command building and
parsing parts through :class:`CommandAdapter` and :class:`CollectorAdapter`.

Rules for adapters:
* never call ``subprocess`` directly — use :mod:`atad.core.execution`;
* ``build_command`` returns a validated argument list, never a shell string;
* ``parse`` is a pure function from saved raw output to evidence, so it can be
  tested with fixture files and no real tool installed.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from importlib import metadata
from typing import Any

from atad.core.execution import resolve_executable, run_command
from atad.core.platform import current_os
from atad.evidence.models import Evidence, utc_now

VERSION_TIMEOUT = 15.0


@dataclass(frozen=True)
class ToolInfo:
    name: str
    available: bool
    version: str | None = None
    path: str | None = None
    reason: str | None = None          # why it is unavailable
    required: bool = False
    detected_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class ParseContext:
    """What a parser needs to know to build evidence records."""

    case_id: str
    host: str
    collection_mode: Any               # CollectionMode
    host_declared: bool = False
    execution_id: int | None = None
    raw_ref: str | None = None
    raw_sha256: str | None = None
    tool_version: str | None = None
    simulated: bool = False
    tool: str | None = None            # overrides the adapter's default tool name


class ToolAdapter(ABC):
    """Base for every tool atad can use."""

    #: short id used in commands and reports, e.g. ``nmap``
    name: str
    #: one-line description shown by ``atad doctor``
    purpose: str = ""
    #: operating systems where the tool applies
    supported_os: frozenset[str] = frozenset({"windows", "linux"})
    #: True when the MVP cannot work without it on a supported OS
    required: bool = False

    def applies_here(self) -> bool:
        return current_os() in self.supported_os

    def detect(self) -> ToolInfo:
        if not self.applies_here():
            return self._info(False, reason=f"not used on {current_os()}")
        return self._detect()

    @abstractmethod
    def _detect(self) -> ToolInfo: ...

    def _info(self, available: bool, **kw: Any) -> ToolInfo:
        return ToolInfo(name=self.name, available=available, required=self.required, **kw)


class ExternalTool(ToolAdapter):
    """A program found on PATH, e.g. ``nmap``."""

    #: candidate executable names, first found wins
    executables: tuple[str, ...] = ()
    #: arguments that print the version
    version_args: tuple[str, ...] = ("--version",)
    #: regex with one group capturing the version
    version_pattern: str = r"(\d+(?:\.\d+)+)"

    def _detect(self) -> ToolInfo:
        for exe in self.executables:
            path = resolve_executable(exe)
            if path:
                return self._info(True, path=path, version=self._version(path))
        names = ", ".join(self.executables)
        return self._info(False, reason=f"not found on PATH ({names})")

    def _version(self, path: str) -> str | None:
        if not self.version_args:
            return None
        res = run_command([path, *self.version_args], timeout=VERSION_TIMEOUT, max_output=64 * 1024)
        text = (res.stdout + b"\n" + res.stderr).decode("utf-8", "replace")
        m = re.search(self.version_pattern, text)
        return m.group(1) if m else None


class PythonLibrary(ToolAdapter):
    """A Python package used in-process, e.g. ``psutil``."""

    module: str
    distribution: str

    def _detect(self) -> ToolInfo:
        if importlib.util.find_spec(self.module) is None:
            if getattr(sys, "frozen", False):          # the single-file atad.exe
                return self._info(False, reason="not included in this build")
            return self._info(False, reason=f"pip install {self.distribution}")
        try:
            version = metadata.version(self.distribution)
        except metadata.PackageNotFoundError:
            version = None
        return self._info(True, version=version, path=f"python:{self.module}")


class CommandAdapter(ExternalTool):
    """An external tool atad runs and parses (implemented from M3 on)."""

    @abstractmethod
    def build_command(self, **params: Any) -> list[str]: ...

    @abstractmethod
    def parse(self, raw: bytes, ctx: ParseContext) -> list[Evidence]: ...


class CollectorAdapter(PythonLibrary):
    """An in-process collector (psutil, hashlib, python-evtx...)."""

    @abstractmethod
    def collect(self, **params: Any) -> bytes:
        """Return the raw capture (e.g. JSON bytes) to be saved and hashed."""

    @abstractmethod
    def parse(self, raw: bytes, ctx: ParseContext) -> list[Evidence]: ...
