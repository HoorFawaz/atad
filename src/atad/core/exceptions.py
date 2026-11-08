# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Exception hierarchy for atad.

Every error raised on purpose by atad derives from :class:`AtadError`, so the
CLI can show a clean message instead of a traceback.
"""


class AtadError(Exception):
    """Base class for all atad errors."""

    exit_code: int = 1


class ValidationError(AtadError):
    """User input failed validation (bad IP, bad path, bad case id...)."""

    exit_code = 2


class ScopeError(ValidationError):
    """A network target is outside the authorized scope or not allowed."""


class CaseNotFoundError(AtadError):
    """The requested case does not exist."""


class CaseExistsError(AtadError):
    """A case folder already exists where a new one would be created."""


class StorageError(AtadError):
    """The case database or case folder could not be read or written."""
