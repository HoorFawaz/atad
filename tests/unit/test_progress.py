# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import io

from atad.core import progress as pg


def test_track_yields_everything_silently_when_not_a_terminal(capsys):
    assert list(pg.track(range(5), "x", 5)) == [0, 1, 2, 3, 4]
    assert capsys.readouterr().err == ""


def test_counter_is_drawn_and_erased(monkeypatch):
    monkeypatch.setattr(pg, "_INTERVAL", 0)
    out = io.StringIO()
    with pg.Progress("hashing files", total=3, stream=out, force=True) as bar:
        for _ in range(3):
            bar.advance(note="a.exe")
    text = out.getvalue()
    assert "hashing files: 3/3  a.exe" in text
    assert text.endswith("\r") and "\n" not in text      # erased, no stray lines


def test_env_switch_turns_it_off(monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setenv("ATAD_NO_PROGRESS", "1")
    out = Tty()
    with pg.Progress("x", stream=out) as bar:
        bar.advance()
    assert out.getvalue() == ""
