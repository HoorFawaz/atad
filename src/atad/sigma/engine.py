# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Run Sigma rules over a case's evidence and turn matches into findings.

One finding per rule and host, listing every matching record. Under the
Detection Rule License used by SigmaHQ, a message based on a match must keep
the rule's author, so every finding names it.

| Sigma level   | Severity | Category    |   | Sigma status | Confidence |
|---------------|----------|-------------|---|--------------|------------|
| critical      | critical | suspicious  |   | stable       | high       |
| high          | high     | suspicious  |   | test         | medium     |
| medium        | medium   | suspicious  |   | experimental | low        |
| low           | low      | observation |   |              |            |
| informational | info     | observation |   |              |            |
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from atad.evidence.models import (
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    Severity,
)
from atad.sigma.fields import applies_to_tags, source_tags, to_event
from atad.sigma.rules import LoadReport, SigmaRule, load_rules

SEVERITY = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
            "low": Severity.LOW, "informational": Severity.INFO}
CONFIDENCE = {"stable": Confidence.HIGH, "test": Confidence.MEDIUM}
MAX_LISTED = 200


def default_rules_path() -> Path | None:
    """$ATAD_SIGMA (``none`` turns Sigma off), else ./rules/sigma when it exists."""
    env = os.environ.get("ATAD_SIGMA")
    if env:
        return None if env.strip().lower() == "none" else Path(env)
    p = Path("rules/sigma")
    return p if p.is_dir() else None


@dataclass
class SigmaRun:
    load: LoadReport
    findings: list[Finding] = field(default_factory=list)
    matched_rules: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)


def _host_key(h: str) -> str:
    return h.strip().lower().split(".")[0]


def _fields_shown(rule: SigmaRule, ev: dict) -> str:
    keys = ("Image", "CommandLine", "ParentImage", "TargetFilename", "DestinationIp",
            "DestinationPort", "DestinationHostname", "User", "TargetUserName", "IpAddress",
            "exe", "message")
    parts = [f"{k}={str(ev[k])[:120]}" for k in keys if ev.get(k) not in (None, "")]
    return ", ".join(parts[:5])


def run_sigma(case_id: str, evidence: list[Evidence], path: Path) -> SigmaRun:
    run = SigmaRun(load=load_rules(path))
    # Group records by their log-source tags once; each rule then looks only at
    # the groups its logsource selects.
    groups: dict[frozenset, list[Evidence]] = defaultdict(list)
    for e in evidence:
        tags = source_tags(e)
        if tags:
            groups[tags].append(e)
    events = {e.id: to_event(e) for g in groups.values() for e in g}
    for rule in run.load.rules:
        hits: dict[str, list[Evidence]] = defaultdict(list)
        candidates = [e for tags, g in groups.items() if applies_to_tags(rule.logsource, tags) for e in g]
        for e in candidates:
            try:
                if rule.match(events[e.id]):
                    hits[_host_key(e.host)].append(e)
            except Exception as exc:  # noqa: BLE001 - a broken rule must not stop the others
                run.errors.append((rule.title, str(exc)))
                break
        if hits:
            run.matched_rules += 1
        for _, evs in sorted(hits.items()):
            evs.sort(key=lambda x: (x.event_time is None, x.event_time, x.id))
            first = evs[0]
            sev = SEVERITY.get(rule.level, Severity.MEDIUM)
            category = (FindingCategory.SUSPICIOUS if sev in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
                        else FindingCategory.OBSERVATION)
            attack = [t for t in rule.tags if t.lower().startswith("attack.t")]
            rationale = (
                f"Sigma rule '{rule.title}'" + (f" ({rule.id})" if rule.id else "")
                + (f" by {rule.author}" if rule.author else "")
                + f", level {rule.level}, status {rule.status}, matched {len(evs)} record(s) on "
                f"{first.host}. First match: {first.summary}"
                + (f" [{_fields_shown(rule, events[first.id])}]" if _fields_shown(rule, events[first.id]) else "")
                + "." + (f" ATT&CK: {', '.join(t[7:].upper() for t in attack)}." if attack else "")
                + (f" Known false positives: {'; '.join(rule.falsepositives)}." if rule.falsepositives else "")
                + f" Rule file {Path(rule.path).name} (SHA-256 {rule.sha256[:16]}…).")
            run.findings.append(Finding(
                case_id=case_id, title=f"Sigma: {rule.title}", description=rule.description[:500],
                category=category, severity=sev, confidence=CONFIDENCE.get(rule.status, Confidence.LOW),
                rule_id="SIGMA", rationale=rationale,
                evidence_ids=[x.id for x in evs[:MAX_LISTED]]))
    return run
