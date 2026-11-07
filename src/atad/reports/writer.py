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
    )


def render_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _write_new(path: Path, text: str) -> None:
    with open(path, "x", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def write_reports(oc: OpenCase, formats: tuple[str, ...] = FORMATS,
                  now: datetime | None = None) -> tuple[list[WrittenReport], dict]:
    now = now or utc_now()
    data = build_report_data(oc, generated_at=now)
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
