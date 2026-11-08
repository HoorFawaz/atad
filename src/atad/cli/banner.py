# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""What `atad` prints when it is run without a command.

On a terminal: the name in block letters, English and Arabic, then the
commands to start with. The Arabic name is drawn, not typed, so it shows
correctly in consoles that cannot shape Arabic text. Piped or redirected
output gets the plain text only. ATAD_NO_BANNER=1 turns the drawing off.
"""

from __future__ import annotations

import os
import shutil
import sys

import typer

from atad import __version__

# 5 x 5 pixel letters. Each pixel is printed as two block characters so it is square.
_LATIN = {
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
}

# عتاد in a square Kufi style, drawn left to right as it appears on screen:
# dal, then alef, teh and ain joined on one base line. Six rows; the last is the base line.
_ARABIC = [
    "      #              ",
    "      #              ",
    " ##   #    # #   ####",
    "   #  #          #   ",
    "    # #     #    #   ",
    "##### ###############",
]

QUICK_START = [
    ("atad demo", "try a simulated case"),
    ("atad triage --profile soc", "first look at this machine"),
    ("atad triage --profile dfir", "full investigation with exports"),
    ("atad doctor", "check installed tools"),
    ("atad --help", "all commands"),
]

_PIXEL = "██"
_GAP = "      "


def latin_art() -> list[str]:
    rows = [" ".join(_LATIN[c][r] for c in "ATAD") for r in range(5)]
    return [_pixels(r) for r in [" " * len(rows[0]), *rows]]      # line up with the Arabic base line


def arabic_art() -> list[str]:
    return [_pixels(r) for r in _ARABIC]


def _pixels(row: str) -> str:
    return "".join(_PIXEL if ch == "#" else "  " for ch in row).rstrip()


def art(width: int) -> list[str]:
    """Side by side when the terminal is wide enough, otherwise one above the other."""
    en, ar = latin_art(), arabic_art()
    en_w = max(len(r) for r in en)
    if en_w + len(_GAP) + max(len(r) for r in ar) + 2 <= width:
        return [("  " + e.ljust(en_w) + _GAP + a).rstrip() for e, a in zip(en, ar, strict=True)]
    if max(len(r) for r in ar) + 2 <= width:
        return ["  " + r for r in en[1:]] + [""] + ["  " + r for r in ar]
    return []


def text_lines() -> list[str]:
    pad = max(len(c) for c, _ in QUICK_START) + 4
    lines = [f"  ATAD {__version__} · Advanced Toolkit for Attack & Defense",
             "  Read-only SOC / DFIR toolkit · ATAD Team",
             "",
             "  Quick start"]
    lines += [f"    {cmd.ljust(pad)}{desc}" for cmd, desc in QUICK_START]
    return lines


def _drawing_wanted(stream) -> bool:
    if os.environ.get("ATAD_NO_BANNER"):
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def show_welcome(stream=None) -> None:
    stream = stream or sys.stdout
    if _drawing_wanted(stream):
        width = shutil.get_terminal_size((100, 24)).columns
        drawing = art(width)
        if drawing:
            typer.echo("", file=stream)
            for row in drawing:
                typer.echo(typer.style(row, fg="yellow"), file=stream)
            typer.echo("", file=stream)
    for line in text_lines():
        if line.strip() in ("Quick start",) or line.startswith("  ATAD "):
            line = typer.style(line, bold=True)
        typer.echo(line, file=stream)
