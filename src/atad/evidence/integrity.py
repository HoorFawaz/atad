# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Hashing helpers used to protect evidence integrity."""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK = 1024 * 1024  # 1 MiB


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    """SHA-256 of a file, read in chunks so large evidence fits in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_file(path: str | Path, expected_sha256: str) -> bool:
    """True when the file still has the hash recorded at collection time."""
    return sha256_file(path) == expected_sha256.lower()
