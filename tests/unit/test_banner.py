# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import io

from typer.testing import CliRunner

from atad.cli import banner
from atad.cli.app import app


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_no_command_shows_quick_start_without_drawing():
    r = CliRunner().invoke(app, [])
    assert r.exit_code == 0, r.output
    assert "Quick start" in r.output and "atad triage --profile soc" in r.output
    assert "█" not in r.output                    # not a terminal: plain text only


def test_drawing_on_a_terminal(monkeypatch):
    monkeypatch.delenv("ATAD_NO_BANNER", raising=False)
    out = _Tty()
    banner.show_welcome(out)
    assert "█" in out.getvalue() and "Quick start" in out.getvalue()


def test_drawing_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("ATAD_NO_BANNER", "1")
    out = _Tty()
    banner.show_welcome(out)
    assert "█" not in out.getvalue() and "Quick start" in out.getvalue()


def test_art_fits_the_terminal_width():
    wide, narrow = banner.art(130), banner.art(90)
    assert len(wide) == 6 and all(len(r) <= 130 for r in wide)
    assert len(narrow) > 6 and all(len(r) <= 90 for r in narrow)
    assert banner.art(30) == []


def test_subcommands_still_work():
    r = CliRunner().invoke(app, ["--version"])
    assert r.exit_code == 0 and "Quick start" not in r.output
