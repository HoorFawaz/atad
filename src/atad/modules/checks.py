"""Check selection shared by every module (``--only`` / ``--skip``)."""

from __future__ import annotations

from dataclasses import dataclass

from atad.core.exceptions import ValidationError


@dataclass(frozen=True)
class CheckSelection:
    selected: list[str]   # checks to run, in the module's order
    excluded: list[str]   # checks left out by the analyst


def _parse(value: str | None) -> list[str]:
    if not value:
        return []
    return [p.strip().lower() for p in value.split(",") if p.strip()]


def select_checks(available: list[str], only: str | None = None, skip: str | None = None) -> CheckSelection:
    """Resolve ``--only`` / ``--skip`` against a module's check names.

    * both together is an error;
    * unknown names are an error that lists the valid ones;
    * the result keeps the module's own order.
    """
    if only and skip:
        raise ValidationError("use either --only or --skip, not both")
    wanted = _parse(only) if only else []
    unwanted = _parse(skip) if skip else []
    unknown = [c for c in wanted + unwanted if c not in available]
    if unknown:
        raise ValidationError(
            f"unknown check(s): {', '.join(unknown)}. Valid: {', '.join(available)}"
        )
    if only is not None and not wanted:
        raise ValidationError("--only needs at least one check name")
    if wanted:
        selected = [c for c in available if c in wanted]
    else:
        selected = [c for c in available if c not in unwanted]
    if not selected:
        raise ValidationError("no checks left to run")
    excluded = [c for c in available if c not in selected]
    return CheckSelection(selected, excluded)
