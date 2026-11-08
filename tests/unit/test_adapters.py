# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import sys

from atad.adapters.base import ExternalTool, PythonLibrary
from atad.adapters.catalog import ALL_TOOLS, Sysmon
from atad.core import platform as plat
from atad.core.tool_registry import ToolRegistry


class FakePython(ExternalTool):
    """Uses the Python interpreter as a stand-in for an external tool."""
    name = "fakepy"
    executables = (sys.executable,)
    version_args = ("--version",)
    version_pattern = r"Python (\S+)"


class MissingTool(ExternalTool):
    name = "missing"
    executables = ("atad-not-installed-1", "atad-not-installed-2")
    required = True


class WindowsOnly(ExternalTool):
    name = "winonly"
    executables = (sys.executable,)
    supported_os = frozenset({"windows"})


class PytestLib(PythonLibrary):
    name = "pytest"
    module = "pytest"
    distribution = "pytest"


class NoLib(PythonLibrary):
    name = "nolib"
    module = "atad_no_such_module"
    distribution = "atad-no-such-module"


def test_external_detected_with_version():
    info = FakePython().detect()
    assert info.available and info.path == sys.executable
    assert info.version == sys.version.split()[0]


def test_missing_external_reports_reason():
    info = MissingTool().detect()
    assert not info.available and info.required
    assert "atad-not-installed-1" in info.reason


def test_os_filter(monkeypatch):
    monkeypatch.setattr("atad.adapters.base.current_os", lambda: "linux")
    info = WindowsOnly().detect()
    assert not info.available and "not used on linux" in info.reason
    monkeypatch.setattr("atad.adapters.base.current_os", lambda: "windows")
    assert WindowsOnly().detect().available


def test_python_library_detection():
    assert PytestLib().detect().available
    info = NoLib().detect()
    assert not info.available and "pip install atad-no-such-module" == info.reason


def test_sysmon_without_wevtutil(monkeypatch):
    monkeypatch.setattr("atad.adapters.base.current_os", lambda: "windows")
    monkeypatch.setattr("atad.adapters.catalog.resolve_executable", lambda name: None)
    info = Sysmon().detect()
    assert not info.available and "wevtutil" in info.reason


def test_registry_caches_and_lists():
    reg = ToolRegistry([FakePython(), MissingTool()])
    assert reg.names() == ["fakepy", "missing"]
    first = reg.detect("fakepy")
    assert reg.detect("fakepy") is first          # cached
    assert reg.detect("fakepy", refresh=True) is not first
    assert [i.available for i in reg.detect_all()] == [True, False]


def test_catalog_names_unique_and_detect_never_raises():
    names = [cls.name for cls in ALL_TOOLS]
    assert len(names) == len(set(names))
    for info in ToolRegistry().detect_all():
        assert info.available or info.reason


def test_platform_helpers():
    assert plat.current_os() in {"windows", "linux", "macos", sys.platform}
    assert plat.local_hostname()
    assert plat.is_elevated() in (True, False, None)
