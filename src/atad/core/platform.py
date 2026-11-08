# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Operating-system and privilege detection."""

from __future__ import annotations

import os
import platform
import socket
import sys

WINDOWS = "windows"
LINUX = "linux"
MACOS = "macos"


def current_os() -> str:
    if sys.platform.startswith("win"):
        return WINDOWS
    if sys.platform.startswith("linux"):
        return LINUX
    if sys.platform == "darwin":
        return MACOS
    return sys.platform


def os_description() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def local_hostname() -> str:
    """Hostname of the machine atad runs on (used for local-mode evidence)."""
    return socket.gethostname()


def is_elevated() -> bool | None:
    """True when running as Administrator / root. None if it cannot be told."""
    try:
        if current_os() == WINDOWS:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return None
