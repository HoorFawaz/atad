"""Shared CLI state and error handling."""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar

import typer

from atad.cases.manager import CaseManager, OpenCase
from atad.core.exceptions import AtadError

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class _State:
    home: Path | None = None

    def manager(self) -> CaseManager:
        return CaseManager(self.home)


state = _State()


def get_or_create_case(case_id: str | None, auto_name: str) -> tuple[OpenCase, bool]:
    """Open ``case_id``, or create a new case when none is given.

    Returns (case, created).
    """
    mgr = state.manager()
    if case_id:
        return mgr.open_case(case_id), False
    oc = mgr.create_case(auto_name)
    typer.secho(f"Created {oc.case.id} ({oc.path})", fg=typer.colors.GREEN)
    return oc, True


def handle_errors(func: F) -> F:
    """Turn atad errors into a clean message and the right exit code."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except AtadError as exc:
            typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=exc.exit_code) from None

    return wrapper  # type: ignore[return-value]
