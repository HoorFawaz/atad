import pytest

from atad.cases.manager import CaseManager


@pytest.fixture
def manager(tmp_path):
    return CaseManager(tmp_path / "cases")


@pytest.fixture
def case(manager):
    return manager.create_case("Unit test case", simulated=True)
