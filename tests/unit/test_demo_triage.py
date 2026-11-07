# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

from dataclasses import dataclass, field

import pytest

from atad import triage as tr
from atad.adapters.base import ToolInfo
from atad.adapters.catalog import YaraPython
from atad.correlation.engine import correlate
from atad.demo.builder import build_demo, dropper_sha256, load_scenario
from atad.demo.evaluate import evaluate
from atad.evidence.models import (
    CollectionMode,
    Execution,
    ExecutionStatus,
    SourceModule,
)

# --------------------------------------------------------------------------- demo


def test_scenario_is_simulated_and_labelled():
    s = load_scenario()
    assert "SIMULATED" in s["_note"] and s["expected"] and s["decoys"]
    assert len(dropper_sha256(s)) == 64


def test_demo_scores_and_evidence_is_simulated(manager):
    b = build_demo(manager)
    assert b.case.case.simulated
    evidence = b.case.repo.list_evidence()
    assert evidence and all(e.simulated for e in evidence)
    r = correlate(b.case.repo)
    avail = {"yara"} if b.yara_available else set()
    m = evaluate(r.findings, b.scenario["expected"], available=avail)
    assert (m.precision, m.recall) == (1.0, 1.0), m.as_dict()
    if not b.yara_available:
        assert {e["rule"] for e in m.not_testable} == {"YARA", "R3"}


def test_demo_without_yara_marks_untestable(manager, monkeypatch):
    monkeypatch.setattr(YaraPython, "detect",
                        lambda self: ToolInfo(name="yara-python", available=False,
                                              reason="not installed (test)"))
    b = build_demo(manager)
    assert b.yara_available is False
    m = evaluate(correlate(b.case.repo).findings, b.scenario["expected"])
    assert {e["rule"] for e in m.not_testable} == {"YARA", "R3"}
    assert (m.precision, m.recall) == (1.0, 1.0), m.as_dict()


def test_evaluate_counts_misses_and_extras(manager):
    b = build_demo(manager)
    findings = correlate(b.case.repo).findings
    dropped = [f for f in findings if f.rule_id != "S1"]
    m = evaluate(dropped, b.scenario["expected"], available={"yara"} if b.yara_available else set())
    assert [e["rule"] for e in m.fn] == ["S1"] and m.recall < 1.0
    extra = findings[0].model_copy(update={"id": "FND-9999", "title": "something else"})
    m = evaluate(findings + [extra], b.scenario["expected"],
                 available={"yara"} if b.yara_available else set())
    assert [f.id for f in m.fp] == ["FND-9999"] and m.precision < 1.0


# ------------------------------------------------------------------------- triage


@dataclass
class _Outcome:
    execution: Execution


@dataclass
class _Result:
    outcomes: list
    evidence: list = field(default_factory=list)


def _ex(case, status, error=None, tool="t"):
    return Execution(case_id=case.case.id, module=SourceModule.HOST, tool=tool,
                     collection_mode=CollectionMode.LOCAL, status=status, error=error)


@pytest.fixture
def fake_modules(case, monkeypatch):
    calls = {}

    def fake(name, statuses):
        def run(oc, checks, **kw):
            calls[name] = (checks, kw)
            return _Result([_Outcome(_ex(case, s, e)) for s, e in statuses])
        return run

    monkeypatch.setattr(tr, "run_host", fake("host", [(ExecutionStatus.SUCCESS, None),
                                                      (ExecutionStatus.UNAVAILABLE, "Windows only")]))
    monkeypatch.setattr(tr, "run_log_live", fake("logs", [(ExecutionStatus.FAILED, "access denied")]))
    monkeypatch.setattr(tr, "run_net", fake("net", [(ExecutionStatus.SUCCESS, None)]))
    monkeypatch.setattr(tr, "run_files",
                        lambda oc, path, checks, **kw: calls.setdefault("files", (path, kw))
                        and _Result([_Outcome(_ex(case, ExecutionStatus.SUCCESS))]))
    return calls


def test_triage_soc_profile(case, fake_modules, tmp_path):
    r = tr.run_triage(case, tr.PROFILES["soc"], tr.MODULES, target="10.0.0.5", path=tmp_path)
    steps = {s.name: s.status for s in r.steps}
    assert steps == {"host": "limited", "logs": "failed", "files": "done", "net": "done"}
    assert r.partial
    assert fake_modules["logs"][1]["hours"] == 24
    assert fake_modules["net"][0] == ["interfaces", "ping", "dns"]      # never scans
    assert {w.format for w in r.reports} == {"html", "json"} and r.exports == []


def test_triage_full_scans_and_exports(case, fake_modules):
    r = tr.run_triage(case, tr.PROFILES["full"], tr.MODULES, target="10.0.0.5")
    assert "scan" in fake_modules["net"][0] and fake_modules["net"][1]["profile"] == "quick"
    assert fake_modules["logs"][1]["hours"] == 168
    assert [p.suffix for p in r.exports] == [".csv", ".jsonl", ".zip"]
    assert {s.name: s.status for s in r.steps}["files"] == "skipped"     # no --path


def test_triage_without_target_only_interfaces(case, fake_modules):
    tr.run_triage(case, tr.PROFILES["dfir"], ["net"])
    assert fake_modules["net"][0] == ["interfaces"]
    assert "host" not in fake_modules and "logs" not in fake_modules


def test_triage_hours_override(case, fake_modules):
    tr.run_triage(case, tr.PROFILES["soc"], ["logs"], hours=6)
    assert fake_modules["logs"][1]["hours"] == 6
