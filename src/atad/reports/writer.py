# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Write JSON and HTML reports into the case's ``reports/`` folder.

Each report is a new, read-only file with its SHA-256 recorded in the case
database, so a report handed to someone else can be checked later.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from pathlib import Path

import jinja2

from atad.cases.manager import OpenCase
from atad.evidence.integrity import sha256_file
from atad.evidence.models import utc_now
from atad.reports.builder import (
    DEFAULT_TLP,
    RULE_DESCRIPTIONS,
    SEVERITY_ORDER,
    build_report_data,
    file_stamp,
    relative,
    report_problems,
)

FORMATS = ("html", "json")
HTML_LIMITS = {"timeline": 2000, "evidence": 3000, "iocs": 500}


@dataclass
class WrittenReport:
    format: str
    path: Path
    relative_path: str
    sha256: str


def _short_time(value: str | None) -> str:
    if not value:
        return ""
    return value[:19].replace("T", " ")


def render_html(data: dict) -> str:
    source = (resources.files("atad.reports") / "templates" / "report.html.j2").read_text(
        encoding="utf-8")
    env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined,
                             trim_blocks=False, lstrip_blocks=False)
    env.filters["t"] = _short_time
    template = env.from_string(source)
    return template.render(
        r=data,
        problems=report_problems(data),
        limits=HTML_LIMITS,
        ev_by_id={e["id"]: e for e in data["evidence"]},
        findings_by_id={f["id"]: f for f in data["findings"]},
        rules=RULE_DESCRIPTIONS,
        severities=SEVERITY_ORDER,
        summary_text=executive_summary(data),
    )


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def executive_summary(data: dict) -> list[str]:
    """Plain-language paragraphs for the executive summary, built only from the data."""
    s = data["summary"]
    out = []
    hosts = s["hosts"]
    modules = sorted(s["evidence_by_module"])
    period = (f"between {_short_time(s['first_event'])} and {_short_time(s['last_event'])} UTC"
              if s["first_event"] else "with no event times")
    out.append(
        f"ATAD examined {s['evidence_total']} evidence record(s) "
        + (f"from {_join(hosts)} " if hosts else "")
        + (f"collected by the {_join(modules)} module(s), " if modules else "")
        + f"{period}.")
    if s["findings_total"]:
        parts = [f"{n} {sev}" for sev, n in s["findings_by_severity"].items() if n]
        top = [f for f in data["findings"] if f["category"] != "correlated"][:3]
        out.append(
            f"Correlation produced {s['findings_total']} finding(s): {_join(parts)}. "
            + ("The most serious are: " + "; ".join(f"{f['title']} ({f['id']})" for f in top) + "."
               if top else ""))
        out.append("Findings are leads produced by documented rules (Appendix B). Each lists the "
                   "evidence it rests on; they should be confirmed before any action is taken.")
    else:
        out.append("No rule produced a finding. This does not show that the system is clean: "
                   "see Section 7 for the checks that did not run.")
    integ = s["integrity"]
    if integ["checked"]:
        bad = integ["changed"] + integ["missing"] + integ["unsafe-path"]
        out.append(f"All {integ['checked']} raw evidence file(s) still match the SHA-256 recorded at "
                   "collection." if not bad else
                   f"{bad} of {integ['checked']} raw evidence file(s) no longer match the hash recorded "
                   "at collection (Section 6).")
    return out


def render_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _write_new(path: Path, text: str) -> None:
    with open(path, "x", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def write_reports(oc: OpenCase, formats: tuple[str, ...] = FORMATS,
                  now: datetime | None = None,
                  tlp: str = DEFAULT_TLP) -> tuple[list[WrittenReport], dict]:
    now = now or utc_now()
    data = build_report_data(oc, generated_at=now, tlp=tlp)
    out_dir = oc.path / "reports"
    out_dir.mkdir(exist_ok=True)
    base = f"{oc.case.id}_report_{file_stamp(now)}"
    written = []
    for fmt in formats:
        path = out_dir / f"{base}.{fmt}"
        n = 2
        while path.exists():                      # two reports in the same second
            path = out_dir / f"{base}_{n}.{fmt}"
            n += 1
        text = render_html(data) if fmt == "html" else render_json(data)
        _write_new(path, text)
        digest = sha256_file(path)
        rel = relative(oc, path)
        oc.repo.add_report(fmt, rel, digest, now)
        written.append(WrittenReport(fmt, path, rel, digest))
    return written, data
