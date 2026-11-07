# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Run the correlation rules on a case and rebuild its timeline.

Running again is safe: findings from correlation rules are replaced, never
duplicated. Finding ids keep increasing, so an id that appeared in an older
report never points to a different finding later.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from atad.cases.repository import CaseRepository
from atad.correlation import rules as R
from atad.correlation.config import CorrelationConfig
from atad.evidence.models import Finding


@dataclass
class CorrelationReport:
    findings: list[Finding] = field(default_factory=list)
    removed: int = 0
    timeline_events: int = 0
    evidence_count: int = 0
    ioc_count: int = 0
    disabled: tuple[str, ...] = ()

    @property
    def by_rule(self) -> Counter:
        return Counter(f.rule_id for f in self.findings)


def build_timeline(view: R.CaseView, findings: list[Finding]) -> list[dict]:
    """Every evidence record with an event time, plus one marker per finding
    placed at the time of its earliest evidence."""
    events = []
    for e in view.evidence:
        if e.event_time is None:
            continue
        events.append({"case_id": view.case_id, "event_time": R.fmt_iso(e.event_time),
                       "host": e.host, "description": e.summary,
                       "evidence_id": e.id, "finding_id": None})
    for f in findings:
        t, host = R.finding_time_and_host(view, f)
        if t is None:
            continue
        events.append({"case_id": view.case_id, "event_time": R.fmt_iso(t),
                       "host": host or "?",
                       "description": f"[{f.id} · {f.severity.value}] {f.title}",
                       "evidence_id": None, "finding_id": f.id})
    # Same second: the evidence first, then the finding that explains it.
    events.sort(key=lambda x: (x["event_time"], x["finding_id"] is not None,
                               x["evidence_id"] or "", x["finding_id"] or ""))
    return events


def correlate(repo: CaseRepository, cfg: CorrelationConfig | None = None) -> CorrelationReport:
    cfg = cfg or CorrelationConfig()
    case = repo.get_case()
    view = R.CaseView(case.id, repo.list_evidence(), repo.list_iocs())
    on = lambda rule: rule not in cfg.disabled_rules  # noqa: E731

    removed = repo.delete_findings_by_rules(list(R.ALL_RULES))

    base: list[R.RuleResult] = []
    if on("IOC"):
        base += R.rule_ioc(view)
    if on("YARA"):
        base += R.rule_yara(view)
    if on("S1"):
        base += R.rule_encoded_powershell(view)
    if on("S2"):
        base += R.rule_disguised_file(view)
    if on("S3"):
        base += R.rule_suspicious_autostart(view)
    if on("R1"):
        base += R.rule_bruteforce(view, cfg)
    if on("R2"):
        base += R.rule_ioc_connection(view)
    if on("R3"):
        base += R.rule_flagged_file_executed(view)

    stored = repo.add_findings_many([r.finding for r in base])
    keyed = [(f, r.keys) for f, r in zip(stored, base)]

    extra: list[Finding] = []
    if on("R4"):
        extra += R.rule_pivot(view, keyed)
    if on("R5"):
        extra += R.rule_cluster(view, stored, cfg)
    stored += repo.add_findings_many(extra)

    # Findings added by hand or by other modules stay in the timeline too.
    all_findings = repo.list_findings()
    timeline = build_timeline(view, all_findings)
    repo.replace_timeline(timeline)

    return CorrelationReport(findings=stored, removed=removed,
                             timeline_events=len(timeline),
                             evidence_count=len(view.evidence),
                             ioc_count=len(view.iocs), disabled=cfg.disabled_rules)
