# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Shortcut (.lnk) targets and Windows command-line paths, from cases seen on a
real Windows 11 laptop (Webex Run key, Office 'Send to OneNote' shortcut)."""

import struct

from atad.modules.host import collector as hc
from atad.modules.host.lnk import CLSID, parse_lnk, read_lnk

HAS_LINK_INFO, HAS_ARGUMENTS, HAS_WORK_DIR, IS_UNICODE = 0x02, 0x20, 0x10, 0x80


def make_lnk(local_path=None, arguments=None, workdir=None, env_target=None, unicode_info=False):
    """Build a shortcut following [MS-SHLLINK]."""
    flags = IS_UNICODE
    body = b""
    if local_path:
        flags |= HAS_LINK_INFO
        if unicode_info:
            hdr = 0x24
            ansi = local_path.encode("cp1252", "replace") + b"\x00"
            wide = local_path.encode("utf-16-le") + b"\x00\x00"
            base = hdr
            suffix = base + len(ansi)
            base_u = suffix + 1
            suffix_u = base_u + len(wide)
            tail = ansi + b"\x00" + wide + b"\x00\x00"
            size = hdr + len(tail)
            body += struct.pack("<9I", size, hdr, 1, 0, base, 0, suffix, base_u, suffix_u) + tail
        else:
            hdr = 0x1C
            ansi = local_path.encode("cp1252") + b"\x00"
            base = hdr
            suffix = base + len(ansi)
            tail = ansi + b"\x00"
            body += struct.pack("<7I", hdr + len(tail), hdr, 1, 0, base, 0, suffix) + tail
    for bit, value in ((HAS_WORK_DIR, workdir), (HAS_ARGUMENTS, arguments)):
        if value:
            flags |= bit
            body += struct.pack("<H", len(value)) + value.encode("utf-16-le")
    if env_target:
        ansi = env_target.encode("cp1252").ljust(260, b"\x00")
        wide = env_target.encode("utf-16-le").ljust(520, b"\x00")
        body += struct.pack("<2I", 8 + 260 + 520, 0xA0000001) + ansi + wide
    body += struct.pack("<I", 0)                                   # terminal block
    header = struct.pack("<I", 0x4C) + CLSID + struct.pack("<I", flags) + b"\x00" * (0x4C - 24)
    return header + body


def test_local_path_and_arguments():
    t = parse_lnk(make_lnk("C:\\Program Files\\Microsoft Office\\root\\Office16\\ONENOTEM.EXE",
                           arguments="/tsr", workdir="C:\\Users\\u"))
    assert t.path.endswith("ONENOTEM.EXE") and t.arguments == "/tsr" and t.source == "link info"
    t = parse_lnk(make_lnk("C:\\Tools\\مثال.exe", unicode_info=True))
    assert t.path == "C:\\Tools\\مثال.exe"


def test_environment_block(monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", "C:\\Users\\u\\AppData\\Local")
    t = parse_lnk(make_lnk(env_target="%LOCALAPPDATA%\\CiscoSparkLauncher\\CiscoCollabHost.exe"))
    assert t.path == "C:\\Users\\u\\AppData\\Local\\CiscoSparkLauncher\\CiscoCollabHost.exe"
    assert t.source == "environment block"


def test_bad_shortcuts_never_raise(tmp_path):
    good = make_lnk("C:\\a.exe")
    assert parse_lnk(b"not a shortcut") is None
    assert parse_lnk(good[:40]) is None
    assert parse_lnk(good[:90]) is None or parse_lnk(good[:90]).path is None
    assert read_lnk(tmp_path / "missing.lnk") is None


def test_unquoted_path_with_spaces_is_resolved_like_windows():
    lnk = "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Webex\\Webex.lnk"
    cmd = lnk + " /minimized /autostartedWithWindows=true"
    assert hc.executable_from_command(cmd, exists=lambda p: p == lnk) == lnk
    # without the file on disk the .lnk extension still ends the path
    assert hc.executable_from_command(cmd, exists=lambda p: False) == lnk
    assert hc.executable_from_command("C:\\Program Files\\App\\app -x",
                                      exists=lambda p: p == "C:\\Program Files\\App\\app.exe") \
        == "C:\\Program Files\\App\\app.exe"
    assert hc.executable_from_command('"C:\\a b\\x.exe" -y') == "C:\\a b\\x.exe"


def _shortcut(path):
    from atad.modules.host.lnk import ShortcutTarget
    return lambda _p: ShortcutTarget(path=path, arguments=None, working_dir=None, source="link info")


STARTUP = "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"


def test_startup_shortcut_judged_by_its_target():
    office = hc.assess_startup_item(
        {"type": "startup_folder", "executable": STARTUP + "\\Send to OneNote.lnk"},
        read_shortcut=_shortcut("C:\\Program Files\\Microsoft Office\\root\\Office16\\ONENOTEM.EXE"))
    assert office["suspicious_reasons"] == [] and office["shortcut"].endswith("Send to OneNote.lnk")
    assert office["executable"].endswith("ONENOTEM.EXE")

    bad = hc.assess_startup_item(
        {"type": "startup_folder", "executable": STARTUP + "\\update.lnk"},
        read_shortcut=_shortcut("C:\\Users\\u\\AppData\\Roaming\\upd\\upd.exe"))
    assert bad["suspicious_reasons"] == ["starts from a user-writable folder"]

    unknown = hc.assess_startup_item({"type": "startup_folder", "executable": STARTUP + "\\x.lnk"},
                                     read_shortcut=lambda _p: None)
    assert unknown["shortcut_unresolved"] and unknown["suspicious_reasons"] == []

    direct = hc.assess_startup_item({"type": "startup_folder", "executable": STARTUP + "\\run.vbs"})
    assert direct["suspicious_reasons"] == ["starts from a user-writable folder"]


def test_webex_run_key_is_not_flagged(monkeypatch):
    lnk = "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Webex\\Webex.lnk"
    item = {"type": "registry_run", "name": "CiscoSpark",
            "command": lnk + " /minimized /autostartedWithWindows=true",
            "executable": hc.executable_from_command(lnk + " /minimized", exists=lambda p: p == lnk)}
    out = hc.assess_startup_item(item, read_shortcut=_shortcut(
        "C:\\Users\\u\\AppData\\Local\\CiscoSparkLauncher\\CiscoCollabHost.exe"))
    assert out["suspicious_reasons"] == [] and out["executable"].endswith("CiscoCollabHost.exe")


def test_read_lnk_from_disk(tmp_path):
    p = tmp_path / "a.lnk"
    p.write_bytes(make_lnk("C:\\Windows\\notepad.exe"))
    assert read_lnk(p).path == "C:\\Windows\\notepad.exe"


# The "Shortcut to a File" example published by Microsoft in [MS-SHLLINK] section 3:
# a shortcut to C:\test\a.txt.
MS_EXAMPLE = bytes.fromhex(
    "4c0000000114020000000000c0000000000000469b00080020000000d0e9eef21515c901d0e9eef21515c901d0e9eef2"
    "1515c901000000000000000001000000000000000000000000000000bd0014001f50e04fd020ea3a6910a2d808002b30"
    "309d19002f433a5c0000000000000000000000000000000000000046003100000000002c3969a3100074657374000032"
    "0007000400efbe2c3965a32c3969a326000000031e00000000f51e000000000000000000007400650073007400000014"
    "0048003200000000002c3969a32000612e74787400340007000400efbe2c3969a32c3969a3260000002d6e0000000096"
    "010000000000000000000061002e007400780074000000140000003c0000001c000000010000001c0000002d00000000"
    "0000003b0000001100000003000000818a7a301000000000433a5c746573745c612e747874000007002e005c0061002e"
    "00740078007400070043003a005c00740065007300740060000000030000a0580000000000000063687269732d787073"
    "000000000000004078c79447fac746b3565c2dc6b6d115ec46cd7b227fdd11949900137216874a4078c79447fac746b3"
    "565c2dc6b6d115ec46cd7b227fdd11949900137216874a00000000"
)


def test_microsoft_specification_example():
    t = parse_lnk(MS_EXAMPLE)
    assert t.path == "C:\\test\\a.txt" and t.source == "link info"
