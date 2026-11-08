# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from datetime import UTC, datetime

import pytest

from atad.cases.manager import CASE_SUBDIRS
from atad.core.exceptions import CaseNotFoundError, ScopeError, ValidationError
from atad.evidence.integrity import sha256_bytes, sha256_file, verify_file
from atad.evidence.models import (
    CollectionMode,
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    Observable,
    Profile,
    Severity,
    SourceModule,
)


def test_create_case_layout(manager):
    oc = manager.create_case("Suspicious workstation", Profile.DFIR)
    assert oc.case.id == "CASE-001"
    assert (oc.path / "case.db").is_file()
    for sub in CASE_SUBDIRS:
        assert (oc.path / sub).is_dir()
    assert oc.repo.get_case().profile is Profile.DFIR


def test_case_ids_increment_and_list(manager):
    ids = [manager.create_case(f"c{i}").case.id for i in range(3)]
    assert ids == ["CASE-001", "CASE-002", "CASE-003"]
    assert [oc.case.id for oc in manager.list_cases()] == ids


def test_ids_continue_after_gap(manager):
    manager.create_case("a")
    (manager.home / "CASE-007").mkdir()
    assert manager.create_case("b").case.id == "CASE-008"


def test_cases_do_not_share_evidence(manager):
    a = manager.create_case("a")
    b = manager.create_case("b")
    a.repo.add_evidence(_ev(a.case.id))
    assert len(a.repo.list_evidence()) == 1
    assert b.repo.list_evidence() == []


def test_open_missing_case(manager):
    with pytest.raises(CaseNotFoundError):
        manager.open_case("CASE-099")


def test_open_case_rejects_path_tricks(manager):
    with pytest.raises(ValidationError):
        manager.open_case("../../etc")


def test_empty_name_rejected_before_disk_write(manager):
    with pytest.raises(ValidationError, match="case name is required"):
        manager.create_case("   ")
    assert manager.list_cases() == []


# -------------------------------------------------------------------- scope


def test_scope_add_and_dedupe(case, manager):
    t, added = manager.add_scope(case.case.id, "192.168.1.15", note="lab VM")
    assert added and t.value == "192.168.1.15"
    _, again = manager.add_scope(case.case.id, "192.168.1.15")
    assert not again
    assert [x.value for x in case.repo.list_targets()] == ["192.168.1.15"]


def test_scope_rejects_public(case, manager):
    with pytest.raises(ScopeError):
        manager.add_scope(case.case.id, "1.1.1.1")


# ----------------------------------------------------------------- evidence


def _ev(case_id, **kw):
    base = {
        "case_id": case_id,
        "kind": EvidenceKind.NETWORK_CONNECTION,
        "source_module": SourceModule.HOST,
        "source_tool": "psutil",
        "collection_mode": CollectionMode.LOCAL,
        "host": "LAB-WS-01",
        "event_time": datetime(2026, 11, 7, 10, 6, tzinfo=UTC),
        "summary": "powershell.exe -> 10.66.0.9:443",
        "data": {"pid": 4120, "remote_port": 443, "note": "اختبار"},
        "observables": [
            Observable(type="ip", value="10.66.0.9"),
            Observable(type="pid", value="4120"),
        ],
        "simulated": True,
    }
    base.update(kw)
    return Evidence(**base)


def test_evidence_roundtrip(case):
    stored = case.repo.add_evidence(_ev(case.case.id))
    assert stored.id == "EVD-000001"
    loaded = case.repo.get_evidence("EVD-000001")
    assert loaded.model_dump(exclude={"observables"}) == stored.model_dump(exclude={"observables"})
    assert set(loaded.observables) == set(stored.observables)
    assert loaded.data["note"] == "اختبار"


def test_lookup_by_observable(case):
    case.repo.add_evidence(_ev(case.case.id))
    case.repo.add_evidence(_ev(case.case.id, observables=[Observable(type="ip", value="10.66.0.9")]))
    case.repo.add_evidence(_ev(case.case.id, observables=[Observable(type="ip", value="10.0.0.1")]))
    hits = case.repo.find_evidence_by_observable(Observable(type="ip", value=" 10.66.0.9"))
    assert hits == ["EVD-000001", "EVD-000002"]


def test_finding_links_existing_evidence_only(case):
    e1 = case.repo.add_evidence(_ev(case.case.id))
    e2 = case.repo.add_evidence(_ev(case.case.id))
    f = case.repo.add_finding(Finding(
        case_id=case.case.id,
        title="Connection to IOC IP from PowerShell",
        category=FindingCategory.CORRELATED,
        severity=Severity.HIGH,
        rule_id="R2",
        rationale="same IP in both records",
        evidence_ids=[e1.id, e2.id],
    ))
    assert f.id == "FND-0001"
    assert case.repo.list_findings()[0].evidence_ids == [e1.id, e2.id]

    with pytest.raises(ValidationError, match="unknown evidence"):
        case.repo.add_finding(Finding(
            case_id=case.case.id, title="bad", category=FindingCategory.SUSPICIOUS,
            evidence_ids=["EVD-999999"],
        ))
    assert len(case.repo.list_findings()) == 1  # nothing half-written


# ---------------------------------------------------------------- integrity


def test_hashing(tmp_path):
    p = tmp_path / "raw.txt"
    p.write_bytes(b"abc")
    known = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_bytes(b"abc") == known
    assert sha256_file(p) == known
    assert verify_file(p, known.upper())
    p.write_bytes(b"abd")
    assert not verify_file(p, known)
