# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""A one-line progress counter for long steps ("hashing files 120/800").

Written to stderr, only when stderr is a terminal, at most a few times per
second, and erased when the step ends — so piped or redirected output,
logs and reports never contain it. ATAD_NO_PROGRESS=1 turns it off.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from types import TracebackType
from typing import TypeVar

T = TypeVar("T")

_INTERVAL = 0.25          # seconds between redraws


def _enabled(stream) -> bool:
    if os.environ.get("ATAD_NO_PROGRESS"):
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


class Progress:
    """``with Progress("hashing files", total=800) as p: ... p.advance()``"""

    def __init__(self, label: str, total: int | None = None, *, stream=None,
                 force: bool | None = None) -> None:
        self.label = label
        self.total = total
        self.done = 0
        self.stream = stream or sys.stderr
        self.active = _enabled(self.stream) if force is None else force
        self._last = 0.0
        self._width = 0

    def __enter__(self) -> Progress:
        self._draw(force=True)
        return self

    def advance(self, n: int = 1, note: str = "") -> None:
        self.done += n
        if self.active and time.monotonic() - self._last >= _INTERVAL:
            self._draw(note=note)

    def _draw(self, force: bool = False, note: str = "") -> None:
        if not self.active:
            return
        count = f"{self.done:,}/{self.total:,}" if self.total else f"{self.done:,}"
        text = f"  {self.label}: {count}" + (f"  {note[:60]}" if note else "")
        pad = max(0, self._width - len(text))
        self.stream.write("\r" + text + " " * pad)
        self.stream.flush()
        self._width = len(text)
        self._last = time.monotonic()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        if self.active and self._width:
            self.stream.write("\r" + " " * self._width + "\r")
            self.stream.flush()


def track(items: Iterable[T], label: str, total: int | None = None,
          note: Callable[[T], str] | None = None) -> Iterator[T]:
    """``for p in track(files, "YARA scan", len(files)): ...`` — counts each item."""
    with Progress(label, total=total) as bar:
        for item in items:
            bar.advance(note=note(item) if note else "")
            yield item
