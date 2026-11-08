# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Read the target of a Windows shortcut (.lnk) without running it.

Follows Microsoft's Shell Link Binary File Format [MS-SHLLINK]:
header (76 bytes) → optional LinkTargetIDList → optional LinkInfo (local base
path) → optional strings (name, relative path, working dir, arguments, icon)
→ extra data blocks (EnvironmentVariableDataBlock, signature 0xA0000001).

Only the fields needed to judge an auto-start entry are read. Anything that
does not fit the format returns None; a damaged shortcut never raises.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

HEADER_SIZE = 0x4C
CLSID = bytes.fromhex("0114020000000000C000000000000046")
HAS_ID_LIST, HAS_LINK_INFO, HAS_NAME, HAS_REL_PATH = 0x01, 0x02, 0x04, 0x08
HAS_WORK_DIR, HAS_ARGUMENTS, HAS_ICON, IS_UNICODE = 0x10, 0x20, 0x40, 0x80
ENV_BLOCK = 0xA0000001
MAX_SIZE = 1024 * 1024


@dataclass
class ShortcutTarget:
    path: str | None            # program the shortcut starts
    arguments: str | None
    working_dir: str | None
    source: str                 # which part of the file gave the path


def _cstr(data: bytes, start: int, wide: bool) -> str:
    if wide:
        end = start
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[start:end].decode("utf-16-le", "replace")
    end = data.find(b"\x00", start)
    return data[start:end if end != -1 else len(data)].decode("cp1252", "replace")


def expand_windows_vars(text: str) -> str:
    """%VAR% expansion with this machine's environment; unknown names stay as written.

    Done here rather than with os.path.expandvars, which reads %VAR% only on Windows.
    """
    return re.sub(r"%([^%\s]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), text)


def _expand(path: str) -> str:
    return expand_windows_vars(path) if "%" in path else path


def parse_lnk(data: bytes) -> ShortcutTarget | None:
    if len(data) < HEADER_SIZE or struct.unpack_from("<I", data, 0)[0] != HEADER_SIZE \
            or data[4:20] != CLSID:
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    pos = HEADER_SIZE
    try:
        if flags & HAS_ID_LIST:
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        local_path = None
        if flags & HAS_LINK_INFO:
            info = pos
            size, hdr, li_flags, _vol, base, _net, suffix = struct.unpack_from("<7I", data, info)
            if li_flags & 0x1:                                   # VolumeIDAndLocalBasePath
                if hdr >= 0x24:
                    base_u, suffix_u = struct.unpack_from("<2I", data, info + 28)
                    local_path = _cstr(data, info + base_u, True) + _cstr(data, info + suffix_u, True)
                else:
                    local_path = _cstr(data, info + base, False) + _cstr(data, info + suffix, False)
            pos += size
        wide = bool(flags & IS_UNICODE)
        strings = {}
        for bit, name in ((HAS_NAME, "name"), (HAS_REL_PATH, "relative"), (HAS_WORK_DIR, "workdir"),
                          (HAS_ARGUMENTS, "arguments"), (HAS_ICON, "icon")):
            if flags & bit:
                count = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                n = count * 2 if wide else count
                strings[name] = data[pos:pos + n].decode("utf-16-le" if wide else "cp1252", "replace")
                pos += n
        env_target = None
        while pos + 8 <= len(data):
            bsize, sig = struct.unpack_from("<2I", data, pos)
            if bsize < 8:
                break
            if sig == ENV_BLOCK and bsize >= 8 + 260 + 520:
                env_target = (_cstr(data, pos + 8 + 260, True) or _cstr(data, pos + 8, False)) or None
            pos += bsize
    except struct.error:
        return None

    if local_path:
        path, source = local_path, "link info"
    elif env_target:
        path, source = _expand(env_target), "environment block"
    elif strings.get("relative"):
        path, source = strings["relative"], "relative path"
    else:
        path, source = None, "none"
    return ShortcutTarget(path=path, arguments=strings.get("arguments") or None,
                          working_dir=strings.get("workdir") or None, source=source)


def read_lnk(path: str | Path) -> ShortcutTarget | None:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_SIZE:
            return None
        target = parse_lnk(p.read_bytes())
    except OSError:
        return None
    if target and target.path and target.source == "relative path":
        # a relative path is relative to the shortcut's own folder
        target.path = str(PureWindowsPath(p.parent) / target.path)
    return target
