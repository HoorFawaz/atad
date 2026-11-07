# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Compare the findings of the demo case with the scenario's labels.

* true positive  — an expected finding that was produced
* false negative — an expected finding that was not produced
* false positive — a produced finding that is not in the labels
* not testable   — an expected finding whose tool is missing (e.g. YARA)

precision = TP / (TP + FP)   — how many findings were right
recall    = TP / (TP + FN)   — how many expected findings were found
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from atad.evidence.models import Finding


@dataclass
class Metrics:
    tp: list[dict] = field(default_factory=list)
    fn: list[dict] = field(default_factory=list)
    fp: list[Finding] = field(default_factory=list)
    not_testable: list[dict] = field(default_factory=list)

    @property
    def precision(self) -> float:
        n = len(self.tp) + len(self.fp)
        return len(self.tp) / n if n else 1.0

    @property
    def recall(self) -> float:
        n = len(self.tp) + len(self.fn)
        return len(self.tp) / n if n else 1.0

    def per_rule(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
        for e in self.tp:
            out[e["rule"]]["tp"] += 1
        for e in self.fn:
            out[e["rule"]]["fn"] += 1
        for f in self.fp:
            out[f.rule_id or "-"]["fp"] += 1
        return dict(sorted(out.items()))

    def as_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4), "recall": round(self.recall, 4),
            "true_positives": [e["title"] for e in self.tp],
            "false_negatives": [e["title"] for e in self.fn],
            "false_positives": [f"{f.id} {f.rule_id} {f.title}" for f in self.fp],
            "not_testable": [f"{e['title']} (needs {e['needs']})" for e in self.not_testable],
            "per_rule": self.per_rule(),
        }


def _label(f: Finding, titles: dict[str, str]) -> str:
    """R4 titles carry a finding id that changes between runs, so an R4 link
    is matched by the title of the finding it starts from."""
    if f.rule_id == "R4":
        origin = f.title.split()[2] if len(f.title.split()) > 2 else ""
        return titles.get(origin, "")
    return f.title


def evaluate(findings: list[Finding], expected: list[dict], *,
             available: set[str] | None = None) -> Metrics:
    available = available or set()
    m = Metrics()
    produced = list(findings)
    titles = {f.id: f.title for f in findings}
    matched: set[str] = set()
    for exp in expected:
        if exp.get("needs") and exp["needs"] not in available:
            m.not_testable.append(exp)
            continue
        key = exp.get("from") if exp["rule"] == "R4" else exp["title"]
        hit = next((f for f in produced if f.rule_id == exp["rule"]
                    and _label(f, titles) == key and f.id not in matched), None)
        if hit:
            matched.add(hit.id)
            m.tp.append(exp)
        else:
            m.fn.append(exp)
    # A labelled finding marked untestable is not scored either way.
    untestable = {(e["rule"], e.get("from") or e["title"]) for e in m.not_testable}
    m.fp = [f for f in produced if f.id not in matched
            and (f.rule_id, _label(f, titles)) not in untestable]
    return m
