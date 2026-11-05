# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from atad.evidence.models import (
    CollectionMode,
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    Observable,
    ObservableType,
    SourceModule,
)

SHA = "A" * 64


def _ev(**kw):
    base = dict(
        case_id="CASE-001",
        kind=EvidenceKind.PROCESS,
        source_module=SourceModule.HOST,
        source_tool="psutil",
        collection_mode=CollectionMode.LOCAL,
        host="LAB-WS-01",
        summary="powershell.exe started",
    )
    base.update(kw)
    return Evidence(**base)


# ---------------------------------------------------------------- observables


@pytest.mark.parametrize(
    "kind,raw,expected",
    [
        (ObservableType.IP, " 10.0.0.5 ", "10.0.0.5"),
        (ObservableType.IP, "2001:DB8::0001", "2001:db8::1"),
        (ObservableType.DOMAIN, "Evil.Example.COM.", "evil.example.com"),
        (ObservableType.SHA256, SHA, "a" * 64),
        (ObservableType.PATH, "C:/Users/Bob/AppData/x.EXE", "c:\\users\\bob\\appdata\\x.exe"),
        (ObservableType.USER, "LAB\\Bob", "lab\\bob"),
        (ObservableType.PID, "0042", "42"),
    ],
)
def test_observable_normalization(kind, raw, expected):
    assert Observable(type=kind, value=raw).value == expected


@pytest.mark.parametrize(
    "kind,raw",
    [
        (ObservableType.IP, "999.1.1.1"),
        (ObservableType.SHA256, "abc"),
        (ObservableType.MD5, "z" * 32),
        (ObservableType.PID, "-1"),
        (ObservableType.DOMAIN, "   "),
    ],
)
def test_observable_rejects_bad_values(kind, raw):
    with pytest.raises(ValidationError):
        Observable(type=kind, value=raw)


def test_same_indicator_gives_equal_observables():
    a = Observable(type="path", value="C:\\Windows\\Temp\\A.exe")
    b = Observable(type="path", value="c:/windows/temp/a.EXE")
    assert a == b


# ------------------------------------------------------------------- evidence


def test_naive_datetime_rejected():
    with pytest.raises(ValidationError, match="timezone-aware"):
        _ev(event_time=datetime(2026, 11, 7, 10, 0))


def test_times_converted_to_utc():
    riyadh = timezone(timedelta(hours=3))
    ev = _ev(event_time=datetime(2026, 11, 7, 13, 0, tzinfo=riyadh))
    assert ev.event_time == datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)
    assert ev.event_time.utcoffset() == timedelta(0)


def test_local_evidence_cannot_have_declared_host():
    with pytest.raises(ValidationError, match="local evidence"):
        _ev(host_declared=True)


def test_imported_evidence_must_declare_host():
    with pytest.raises(ValidationError, match="imported evidence"):
        _ev(collection_mode=CollectionMode.IMPORT)
    ev = _ev(collection_mode=CollectionMode.IMPORT, host_declared=True)
    assert ev.host_declared


def test_empty_host_rejected():
    with pytest.raises(ValidationError):
        _ev(host="   ")


# ------------------------------------------------------------------- findings


def test_correlated_finding_needs_two_evidence():
    with pytest.raises(ValidationError, match="at least 2"):
        Finding(case_id="CASE-001", title="x", category=FindingCategory.CORRELATED,
                evidence_ids=["EVD-000001"])
    f = Finding(case_id="CASE-001", title="x", category=FindingCategory.CORRELATED,
                evidence_ids=["EVD-000001", "EVD-000002"])
    assert len(f.evidence_ids) == 2
