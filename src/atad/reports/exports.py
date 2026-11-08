# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Exports for other tools.

* Timeline as CSV or JSONL. Every row has the three fields Timesketch needs
  (``message``, ``datetime`` in ISO 8601, ``timestamp_desc``); the CSV opens in
  Timeline Explorer, and JSONL rows also carry ``@timestamp`` for Elastic.
* The whole case folder as one zip with a SHA256SUMS.txt manifest, to hand
  a case to another analyst.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import stat
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from atad import __version__
from atad.cases.manager import OpenCase
from atad.correlation.engine import build_timeline
from atad.correlation.rules import CaseView
from atad.evidence.integrity import sha256_file
from atad.evidence.models import utc_now
from atad.reports.builder import file_stamp

TIMELINE_FORMATS = ("csv", "jsonl")
FIELDS = ["datetime", "timestamp", "timestamp_desc", "message", "host", "source", "tool",
          "kind", "evidence_id", "finding_id", "severity", "confidence", "rule_id",
          "observables", "evidence_ids", "raw_ref", "simulated", "case_id"]

# Spreadsheet programs run cells that start with these as formulas.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
_SAFE_FIELDS = {"datetime", "timestamp", "simulated"}


def timeline_rows(oc: OpenCase) -> list[dict]:
    evidence = oc.repo.list_evidence()
    findings = oc.repo.list_findings()
    view = CaseView(oc.case.id, evidence, oc.repo.list_iocs())
    by_finding = {f.id: f for f in findings}
    rows = []
    for t in build_timeline(view, findings):
        when = datetime.fromisoformat(t["event_time"]).astimezone(UTC)
        row = dict.fromkeys(FIELDS, "")
        row.update(datetime=when.isoformat(), timestamp=int(when.timestamp() * 1_000_000),
                   message=t["description"], host=t["host"], case_id=oc.case.id)
        if t["evidence_id"]:
            e = view.by_id[t["evidence_id"]]
            row.update(timestamp_desc="Event Time", source=e.source_module.value,
                       tool=e.source_tool, kind=e.kind.value, evidence_id=e.id,
                       observables="; ".join(f"{o.type.value}={o.value}" for o in e.observables),
                       raw_ref=e.raw_ref or "", simulated=e.simulated)
        else:
            f = by_finding[t["finding_id"]]
            row.update(timestamp_desc="Finding (earliest evidence)", source="correlation",
                       tool=f"atad {__version__}", kind="finding", finding_id=f.id,
                       severity=f.severity.value, confidence=f.confidence.value,
                       rule_id=f.rule_id or "", evidence_ids="; ".join(f.evidence_ids),
                       simulated=any(view.by_id[x].simulated for x in f.evidence_ids
                                     if x in view.by_id))
        rows.append(row)
    return rows


def _csv_safe(key: str, value) -> str:
    text = "" if value is None else str(value)
    if key not in _SAFE_FIELDS and text.startswith(_FORMULA_START):
        return "'" + text
    return text


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: _csv_safe(k, r[k]) for k in FIELDS})
    return buf.getvalue()


def to_jsonl(rows: list[dict]) -> str:
    out = []
    for r in rows:
        obj = {"@timestamp": r["datetime"], **{k: v for k, v in r.items() if v != ""}}
        out.append(json.dumps(obj, ensure_ascii=False))
    return "\n".join(out) + ("\n" if out else "")


def _new_path(folder: Path, stem: str, suffix: str) -> Path:
    path, n = folder / f"{stem}.{suffix}", 2
    while path.exists():
        path, n = folder / f"{stem}_{n}.{suffix}", n + 1
    return path


def _read_only(path: Path) -> None:
    os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def export_timeline(oc: OpenCase, formats: tuple[str, ...] = TIMELINE_FORMATS,
                    now: datetime | None = None) -> tuple[list[tuple[Path, str]], int]:
    """Write the timeline into ``exports/``. Returns [(path, sha256)], row count."""
    now = now or utc_now()
    rows = timeline_rows(oc)
    folder = oc.path / "exports"
    folder.mkdir(exist_ok=True)
    written = []
    for fmt in formats:
        path = _new_path(folder, f"{oc.case.id}_timeline_{file_stamp(now)}", fmt)
        text = to_csv(rows) if fmt == "csv" else to_jsonl(rows)
        # utf-8-sig lets Excel / Timeline Explorer read Arabic and other text correctly
        with open(path, "x", encoding="utf-8-sig" if fmt == "csv" else "utf-8",
                  newline="") as fh:
            fh.write(text)
        _read_only(path)
        written.append((path, sha256_file(path)))
    return written, len(rows)


def export_case(oc: OpenCase, now: datetime | None = None) -> tuple[Path, str, int]:
    """Zip the case folder (without earlier exports) with a SHA256SUMS.txt.

    The database is copied with SQLite's backup API, so the zip holds a
    consistent snapshot. Returns (zip path, zip sha256, file count).
    """
    now = now or utc_now()
    folder = oc.path / "exports"
    folder.mkdir(exist_ok=True)
    target = _new_path(folder, f"{oc.case.id}_case_{file_stamp(now)}", "zip")
    root = oc.path.resolve()
    prefix = oc.case.id

    files: list[tuple[str, Path]] = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or rel.startswith(("exports/", "case.db")):
            continue
        files.append((rel, p))

    sums = []
    with tempfile.TemporaryDirectory() as tmp:
        db_copy = Path(tmp) / "case.db"
        src = sqlite3.connect(oc.repo.db_path)
        dst = sqlite3.connect(db_copy)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        files.insert(0, ("case.db", db_copy))

        with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as z:
            for rel, p in files:
                z.write(p, f"{prefix}/{rel}")
                sums.append(f"{sha256_file(p)}  {rel}")
            z.writestr(f"{prefix}/SHA256SUMS.txt", "\n".join(sums) + "\n")
            z.writestr(f"{prefix}/EXPORT.txt",
                       f"Case {oc.case.id} exported by ATAD {__version__} at "
                       f"{now.astimezone(UTC).isoformat()}.\n"
                       f"Check the files with: sha256sum -c SHA256SUMS.txt (inside {prefix}/)\n")
    _read_only(target)
    return target, sha256_file(target), len(files)

