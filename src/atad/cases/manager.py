# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Case lifecycle: create, list and open investigation cases.

Each case is a folder under the atad home directory::

    <home>/CASE-001/
        case.db  raw/  normalized/  logs/  reports/  exports/
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError as PydanticValidationError

from atad import __version__
from atad.cases.repository import CaseRepository
from atad.core.exceptions import CaseExistsError, CaseNotFoundError, StorageError, ValidationError
from atad.evidence.models import Case, Profile, Target
from atad.utils.validation import validate_case_id, validate_target

CASE_SUBDIRS = ("raw", "normalized", "logs", "reports", "exports")
_CASE_DIR_RE = re.compile(r"^CASE-(\d{3,6})$")


def default_home() -> Path:
    """``ATAD_HOME`` if set, otherwise ``./cases``."""
    return Path(os.environ.get("ATAD_HOME", "cases"))


@dataclass(frozen=True)
class OpenCase:
    case: Case
    path: Path
    repo: CaseRepository


class CaseManager:
    def __init__(self, home: str | Path | None = None) -> None:
        self.home = Path(home) if home is not None else default_home()

    # ------------------------------------------------------------- helpers

    def case_path(self, case_id: str) -> Path:
        return self.home / validate_case_id(case_id)

    def _next_number(self) -> int:
        highest = 0
        if self.home.is_dir():
            for entry in self.home.iterdir():
                m = _CASE_DIR_RE.match(entry.name)
                if m and entry.is_dir():
                    highest = max(highest, int(m.group(1)))
        return highest + 1

    # ----------------------------------------------------------- lifecycle

    def create_case(
        self,
        name: str,
        profile: Profile = Profile.SOC,
        *,
        description: str = "",
        simulated: bool = False,
    ) -> OpenCase:
        """Create the case folder, its sub-folders and its database."""
        # Validate before touching the disk.
        try:
            draft = Case(
                id="CASE-000",
                name=name,
                profile=profile,
                description=description,
                simulated=simulated,
                atad_version=__version__,
            )
        except PydanticValidationError as exc:
            msg = "; ".join(str(e.get("msg", "")).removeprefix("Value error, ") for e in exc.errors())
            raise ValidationError(msg or "invalid case details") from None
        try:
            self.home.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StorageError(f"cannot create cases folder {self.home}: {exc}") from exc

        # mkdir(exist_ok=False) claims the id atomically: if two runs race,
        # the second one moves on to the next number.
        for _ in range(100):
            case_id = f"CASE-{self._next_number():03d}"
            path = self.home / case_id
            try:
                path.mkdir(exist_ok=False)
                break
            except FileExistsError:
                continue
            except OSError as exc:
                raise StorageError(f"cannot create case folder {path}: {exc}") from exc
        else:  # pragma: no cover - would need 100 concurrent creations
            raise CaseExistsError("could not allocate a new case id")

        for sub in CASE_SUBDIRS:
            (path / sub).mkdir()

        case = draft.model_copy(update={"id": case_id})
        repo = CaseRepository(path / "case.db")
        repo.initialize()
        repo.insert_case(case)
        return OpenCase(case=case, path=path, repo=repo)

    def open_case(self, case_id: str) -> OpenCase:
        path = self.case_path(case_id)
        db = path / "case.db"
        if not db.is_file():
            raise CaseNotFoundError(f"case {validate_case_id(case_id)} not found in {self.home}")
        repo = CaseRepository(db)
        return OpenCase(case=repo.get_case(), path=path, repo=repo)

    def list_cases(self) -> list[OpenCase]:
        if not self.home.is_dir():
            return []
        result = []
        for entry in sorted(self.home.iterdir()):
            if _CASE_DIR_RE.match(entry.name) and (entry / "case.db").is_file():
                result.append(self.open_case(entry.name))
        return result

    # --------------------------------------------------------------- scope

    def add_scope(
        self, case_id: str, raw_target: str, *, allow_public: bool = False, note: str = "",
        max_addresses: int | None = None,
    ) -> tuple[Target, bool]:
        """Authorize a network target for a case. Returns (target, newly_added)."""
        oc = self.open_case(case_id)
        limit = {"max_addresses": max_addresses} if max_addresses else {}
        vt = validate_target(raw_target, allow_public=allow_public, **limit)
        target = Target(
            case_id=oc.case.id,
            value=vt.value,
            kind=vt.kind,
            is_public=vt.is_public,
            note=note,
        )
        added = oc.repo.add_target(target)
        return target, added
