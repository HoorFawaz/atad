# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Collect everything a report needs from a case, as plain JSON-ready data.

The JSON report is this data written out; the HTML report is rendered from
it. Both are built from the same dictionary, so they never disagree.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from atad import __version__
from atad.cases.manager import OpenCase
from atad.correlation.engine import build_timeline
from atad.correlation.rules import CaseView
from atad.evidence.integrity import sha256_file
from atad.evidence.models import ExecutionStatus, Finding, utc_now

REPORT_FORMAT = "atad-report"
REPORT_VERSION = 1

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Traffic Light Protocol 2.0 (FIRST) — who may receive the report.
TLP_LEVELS = {
    "clear": "TLP:CLEAR", "green": "TLP:GREEN", "amber": "TLP:AMBER",
    "amber+strict": "TLP:AMBER+STRICT", "red": "TLP:RED",
}
DEFAULT_TLP = "amber"

RULE_DESCRIPTIONS = {
    "IOC": "Evidence contains an indicator from a loaded IOC list",
    "YARA": "A file matched a YARA rule",
    "S1": "PowerShell started with an encoded command",
    "S2": "A file whose real type does not match its name",
    "R1": "Repeated failed logons from one source, with or without a later success",
    "R2": "A process connected to a known indicator",
    "R3": "A file that matched YARA was executed",
    "R4": "A finding's key indicator also seen in another source or event type",
    "R5": "Several suspicious findings close in time on one host (hypothesis)",
}
STATUS_LABEL = {
    "success": "ran",
    "failed": "failed",
    "timeout": "timed out",
    "unavailable": "not available",
    "skipped": "skipped",
}


def iso(t: datetime | None) -> str | None:
    return t.astimezone(timezone.utc).isoformat() if t else None


# --------------------------------------------------------------------------- #
# Integrity: do the raw files still have the hash recorded at collection?
# --------------------------------------------------------------------------- #


@dataclass
class IntegrityItem:
    raw_ref: str
    expected: str
    actual: str | None
    status: str          # verified | changed | missing | unsafe-path

    def as_dict(self) -> dict:
        return {"raw_ref": self.raw_ref, "expected_sha256": self.expected,
                "actual_sha256": self.actual, "status": self.status}


def verify_raw_files(oc: OpenCase) -> list[IntegrityItem]:
    """Re-hash every raw file referenced by an execution or evidence record."""
    refs: dict[str, str] = {}
    for ex in oc.repo.list_executions():
        if ex.raw_ref and ex.raw_sha256:
            refs.setdefault(ex.raw_ref, ex.raw_sha256)
    for ev in oc.repo.list_evidence():
        if ev.raw_ref and ev.raw_sha256:
            refs.setdefault(ev.raw_ref, ev.raw_sha256)
    root = oc.path.resolve()
    items = []
    for ref, expected in sorted(refs.items()):
        path = (oc.path / ref).resolve()
        if root not in path.parents:
            items.append(IntegrityItem(ref, expected, None, "unsafe-path"))
        elif not path.is_file():
            items.append(IntegrityItem(ref, expected, None, "missing"))
        else:
            actual = sha256_file(path)
            items.append(IntegrityItem(ref, expected, actual,
                                       "verified" if actual == expected.lower() else "changed"))
    return items


# --------------------------------------------------------------------------- #
# Report data
# --------------------------------------------------------------------------- #


def _finding_dict(f: Finding, view: CaseView) -> dict:
    evs = [view.by_id[x] for x in f.evidence_ids if x in view.by_id]
    times = [e.event_time for e in evs if e.event_time]
    return {
        "id": f.id, "title": f.title, "description": f.description,
        "category": f.category.value, "severity": f.severity.value,
        "confidence": f.confidence.value, "rule_id": f.rule_id, "rationale": f.rationale,
        "first_seen": iso(min(times)) if times else None,
        "last_seen": iso(max(times)) if times else None,
        "hosts": sorted({e.host for e in evs}),
        "evidence_ids": list(f.evidence_ids),
        "created_at": iso(f.created_at),
    }


def _evidence_dict(e) -> dict:
    d = e.model_dump(mode="json")
    d["observables"] = [{"type": o.type.value, "value": o.value} for o in e.observables]
    return d


def _execution_dict(ex) -> dict:
    excluded = ex.status is ExecutionStatus.SKIPPED and ex.error == "excluded_by_user"
    return {
        "id": ex.id, "module": ex.module.value, "tool": ex.tool, "tool_version": ex.tool_version,
        "command": ex.command, "target": ex.target, "collection_mode": ex.collection_mode.value,
        "started_at": iso(ex.started_at), "finished_at": iso(ex.finished_at),
        "status": ex.status.value,
        "label": "skipped (analyst's choice)" if excluded else STATUS_LABEL[ex.status.value],
        "excluded_by_user": excluded,
        "exit_code": ex.exit_code, "elevated": ex.elevated,
        "raw_ref": ex.raw_ref, "raw_sha256": ex.raw_sha256,
        "error": None if excluded else ex.error,
    }


def build_report_data(oc: OpenCase, generated_at: datetime | None = None,
                      tlp: str = DEFAULT_TLP) -> dict:
    generated_at = generated_at or utc_now()
    if tlp not in TLP_LEVELS:
        raise ValueError(f"unknown TLP level {tlp!r}")
    repo, case = oc.repo, oc.case
    evidence = repo.list_evidence()
    findings = repo.list_findings()
    view = CaseView(case.id, evidence, repo.list_iocs())
    executions = repo.list_executions()
    integrity = verify_raw_files(oc)

    findings_sorted = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity.value),
                                                      f.id))
    times = [e.event_time for e in evidence if e.event_time]
    sev = Counter(f.severity.value for f in findings)
    ex_status = Counter(x["label"] for x in map(_execution_dict, executions))
    integ = Counter(i.status for i in integrity)

    timeline = build_timeline(view, findings)
    return {
        "report": {
            "id": f"{case.id}-R{file_stamp(generated_at)}",
            "format": REPORT_FORMAT, "version": REPORT_VERSION,
            "generated_at": iso(generated_at), "generator": f"ATAD {__version__}",
            "times": "UTC", "classification": TLP_LEVELS[tlp],
        },
        "case": {
            "id": case.id, "name": case.name, "profile": case.profile.value,
            "description": case.description, "simulated": case.simulated,
            "created_at": iso(case.created_at), "atad_version": case.atad_version,
        },
        "summary": {
            "evidence_total": len(evidence),
            "evidence_simulated": sum(e.simulated for e in evidence),
            "evidence_by_module": dict(Counter(e.source_module.value for e in evidence)),
            "evidence_by_kind": dict(Counter(e.kind.value for e in evidence)),
            "hosts": sorted({e.host for e in evidence}),
            "first_event": iso(min(times)) if times else None,
            "last_event": iso(max(times)) if times else None,
            "findings_total": len(findings),
            "findings_by_severity": {s: sev.get(s, 0) for s in SEVERITY_ORDER},
            "findings_by_rule": dict(Counter(f.rule_id or "-" for f in findings)),
            "findings_by_category": dict(Counter(f.category.value for f in findings)),
            "executions_by_status": dict(ex_status),
            "integrity": {"checked": len(integrity), **{k: integ.get(k, 0) for k in
                                                         ("verified", "changed", "missing",
                                                          "unsafe-path")}},
        },
        "findings": [_finding_dict(f, view) for f in findings_sorted],
        "timeline": [
            {"time": t["event_time"], "host": t["host"], "description": t["description"],
             "evidence_id": t["evidence_id"], "finding_id": t["finding_id"]}
            for t in timeline
        ],
        "coverage": [_execution_dict(x) for x in executions],
        "integrity": [i.as_dict() for i in integrity],
        "iocs": [{"type": i.type, "value": i.value, "source": i.source,
                  "confidence": i.confidence.value, "description": i.description}
                 for i in repo.list_iocs()],
        "scope": [{"value": t.value, "kind": t.kind, "public": t.is_public, "note": t.note,
                   "added_at": iso(t.added_at)} for t in repo.list_targets()],
        "evidence": [_evidence_dict(e) for e in evidence],
    }


def report_problems(data: dict) -> list[str]:
    """Things the reader must not miss, shown at the top of every report."""
    out = []
    integ = data["summary"]["integrity"]
    if integ["changed"]:
        out.append(f"{integ['changed']} raw evidence file(s) changed after collection — "
                   "their hash no longer matches.")
    if integ["missing"] or integ["unsafe-path"]:
        out.append(f"{integ['missing'] + integ['unsafe-path']} raw evidence file(s) are missing.")
    failed = [c for c in data["coverage"] if c["status"] in ("failed", "timeout", "unavailable")]
    if failed:
        out.append(f"{len(failed)} check(s) did not run or did not finish — see Coverage. "
                   "No finding from them does not mean nothing happened.")
    return out


def file_stamp(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def relative(oc: OpenCase, path: Path) -> str:
    return path.resolve().relative_to(oc.path.resolve()).as_posix()
