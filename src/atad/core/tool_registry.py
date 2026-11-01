"""Central list of tool adapters and their detection results."""

from __future__ import annotations

from typing import Iterable

from atad.adapters.base import ToolAdapter, ToolInfo


class ToolRegistry:
    def __init__(self, adapters: Iterable[ToolAdapter] | None = None) -> None:
        if adapters is None:
            from atad.adapters.catalog import ALL_TOOLS

            adapters = [cls() for cls in ALL_TOOLS]
        self._adapters = {a.name: a for a in adapters}
        self._cache: dict[str, ToolInfo] = {}

    def names(self) -> list[str]:
        return list(self._adapters)

    def get(self, name: str) -> ToolAdapter:
        return self._adapters[name]

    def detect(self, name: str, *, refresh: bool = False) -> ToolInfo:
        if refresh or name not in self._cache:
            self._cache[name] = self._adapters[name].detect()
        return self._cache[name]

    def detect_all(self, *, refresh: bool = False) -> list[ToolInfo]:
        return [self.detect(n, refresh=refresh) for n in self._adapters]

    def applicable(self) -> list[ToolAdapter]:
        """Adapters that apply to the current operating system."""
        return [a for a in self._adapters.values() if a.applies_here()]
