# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Correlation thresholds. Defaults can be overridden with a YAML file."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path

import yaml

from atad.core.exceptions import ValidationError


@dataclass(frozen=True)
class CorrelationConfig:
    # R1 — brute force followed by a successful logon
    r1_min_failures: int = 5
    r1_window_minutes: int = 10
    # R5 — several suspicious findings close together on one host
    r5_min_findings: int = 3
    r5_window_minutes: int = 15
    # Rules can be switched off by id, e.g. ["S2"]
    disabled_rules: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return asdict(self)


def load_config(path: Path | None) -> CorrelationConfig:
    if path is None:
        return CorrelationConfig()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValidationError(f"cannot read correlation config {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ValidationError("correlation config must be a mapping of setting: value")
    known = {f.name for f in fields(CorrelationConfig)}
    unknown = set(data) - known
    if unknown:
        raise ValidationError(f"unknown setting(s): {', '.join(sorted(unknown))}")
    if "disabled_rules" in data:
        data["disabled_rules"] = tuple(str(r).upper() for r in data["disabled_rules"] or [])
    for k in ("r1_min_failures", "r1_window_minutes", "r5_min_findings", "r5_window_minutes"):
        if k in data and (not isinstance(data[k], int) or data[k] < 1):
            raise ValidationError(f"{k} must be a whole number of at least 1")
    return CorrelationConfig(**data)
