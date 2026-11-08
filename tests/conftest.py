# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import pytest

from atad.cases.manager import CaseManager


@pytest.fixture
def manager(tmp_path):
    return CaseManager(tmp_path / "cases")


@pytest.fixture
def case(manager):
    return manager.create_case("Unit test case", simulated=True)


@pytest.fixture(autouse=True)
def _no_default_sigma_rules(monkeypatch):
    """Tests choose their Sigma rules explicitly; ./rules/sigma must not leak in."""
    monkeypatch.setenv("ATAD_SIGMA", "none")
