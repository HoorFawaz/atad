# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import csv
import hashlib
import io
import json
import os
import re
import stat
import zipfile

import pytest

from atad.core.execution import import_file
from atad.correlation.engine import correlate
from atad.evidence.integrity import sha256_file
from atad.evidence.models import CollectionMode, Evidence, Observable, SourceModule
from atad.reports import exports as ex
from atad.reports.builder import build_report_data, report_problems, verify_raw_files
from atad.reports.writer import render_html, write_reports
from tests.unit.test_correlation import build


@pytest.fixture
def scenario(case):
    build(case)
    correlate(case.repo)
    return case


def _raw(case, tmp_path, name="list.txt", text="203.0.113.50\n"):
    src = tmp_path / name
    src.write_text(text)
    return import_file(case, module=SourceModule.IOC, tool="atad-ioc", source=src)


def test_report_data_shape(scenario):
    d = build_report_data(scenario)
    assert d["report"]["format"] == "atad-report" and d["report"]["version"] == 1
    assert d["case"]["simulated"] is True
    s = d["summary"]
    assert s["findings_total"] == len(d["findings"]) > 0
    assert sum(s["findings_by_severity"].values()) == s["findings_total"]
    sev = [f["severity"] for f in d["findings"]]
    order = ["critical", "high", "medium", "low", "info"]
    assert sev == sorted(sev, key=order.index)
    ids = {e["id"] for e in d["evidence"]}
    assert all(set(f["evidence_ids"]) <= ids for f in d["findings"])
    json.dumps(d)  # fully serializable


def test_html_links_every_finding_to_its_evidence(scenario):
    d = build_report_data(scenario)
    html = render_html(d)
    for f in d["findings"]:
        assert f'id="{f["id"]}"' in html
        for eid in f["evidence_ids"]:
            assert f'href="#{eid}"' in html
    for e in d["evidence"]:
        assert f'<tr id="{e["id"]}">' in html
    assert "Simulated data" in html
    assert "<script" not in html and "http://" not in html.replace("http://evil.example", "")


def test_html_escapes_collected_text(case):
    case.repo.add_evidence(Evidence(
        case_id=case.case.id, kind="file", source_module="files", source_tool="t",
        collection_mode=CollectionMode.LOCAL, host="H",
        summary='<script>alert(1)</script> "x"', data={"name": "<img src=x onerror=alert(1)>"},
        observables=[Observable(type="path", value="C:\\<b>.exe")]))
    html = render_html(build_report_data(case))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html


def test_integrity_detects_changed_and_missing(case, tmp_path):
    good = _raw(case, tmp_path, "a.txt")
    bad = _raw(case, tmp_path, "b.txt")
    gone = _raw(case, tmp_path, "c.txt")
    p = bad.raw_path
    os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
    p.write_text("tampered\n")
    os.chmod(gone.raw_path, stat.S_IWRITE | stat.S_IREAD)
    gone.raw_path.unlink()
    status = {i.raw_ref: i.status for i in verify_raw_files(case)}
    assert status[good.execution.raw_ref] == "verified"
    assert status[bad.execution.raw_ref] == "changed"
    assert status[gone.execution.raw_ref] == "missing"
    problems = report_problems(build_report_data(case))
    assert any("changed after collection" in p for p in problems)
    assert any("missing" in p for p in problems)


def test_written_reports_are_recorded_and_read_only(scenario):
    written, _ = write_reports(scenario)
    assert [w.format for w in written] == ["html", "json"]
    rows = scenario.repo.list_reports()
    assert len(rows) == 2
    for w, row in zip(written, rows, strict=True):
        assert row["path"] == w.relative_path and row["sha256"] == sha256_file(w.path)
        assert not os.access(w.path, os.W_OK) or os.geteuid() == 0
        assert not (w.path.stat().st_mode & stat.S_IWUSR)
    data = json.loads(written[1].path.read_text(encoding="utf-8"))
    assert data["case"]["id"] == scenario.case.id
    again, _ = write_reports(scenario, ("json",))       # same second: a new file
    assert again[0].path != written[1].path


def test_empty_case_report(case):
    written, data = write_reports(case)
    assert data["summary"]["findings_total"] == 0
    assert "No findings" in written[0].path.read_text(encoding="utf-8")


def test_timeline_csv_for_timesketch(scenario):
    rows = ex.timeline_rows(scenario)
    text = ex.to_csv(rows)
    reader = list(csv.DictReader(io.StringIO(text)))
    assert {"message", "datetime", "timestamp_desc"} <= set(reader[0])
    assert len(reader) == len(rows)
    dts = [r["datetime"] for r in reader]
    assert dts == sorted(dts)
    assert all(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?\+00:00$", d) for d in dts)
    marks = [r for r in reader if r["finding_id"]]
    assert marks and all(r["timestamp_desc"] == "Finding (earliest evidence)" for r in marks)
    assert all(r["evidence_ids"] for r in marks)


def test_csv_blocks_spreadsheet_formulas():
    row = dict.fromkeys(ex.FIELDS, "")
    row.update(datetime="2026-11-07T10:00:00+00:00", timestamp=1, message="=HYPERLINK(\"x\")",
               host="@evil", observables="-cmd", timestamp_desc="Event Time")
    out = next(iter(csv.DictReader(io.StringIO(ex.to_csv([row])))))
    assert out["message"].startswith("'=") and out["host"] == "'@evil"
    assert out["observables"] == "'-cmd" and out["datetime"].startswith("2026")


def test_timeline_jsonl_for_elastic(scenario):
    lines = ex.to_jsonl(ex.timeline_rows(scenario)).splitlines()
    objs = [json.loads(x) for x in lines]
    assert all("@timestamp" in o and "message" in o and "timestamp_desc" in o for o in objs)
    assert all(isinstance(o["timestamp"], int) for o in objs)


def test_export_files(scenario):
    written, n = ex.export_timeline(scenario)
    assert n > 0 and [p.suffix for p, _ in written] == [".csv", ".jsonl"]
    assert written[0][0].read_bytes().startswith(b"\xef\xbb\xbf")   # BOM for Excel
    assert all(sha256_file(p) == h for p, h in written)


def test_case_zip(scenario, tmp_path):
    _raw(scenario, tmp_path)
    ex.export_timeline(scenario)                     # must not be inside the zip
    path, digest, n = ex.export_case(scenario)
    assert sha256_file(path) == digest
    cid = scenario.case.id
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        assert f"{cid}/case.db" in names and f"{cid}/SHA256SUMS.txt" in names
        assert not any("/exports/" in x for x in names)
        sums = z.read(f"{cid}/SHA256SUMS.txt").decode().splitlines()
        assert len(sums) == n
        for line in sums:
            h, rel = line.split("  ", 1)
            assert hashlib.sha256(z.read(f"{cid}/{rel}")).hexdigest() == h
        db = tmp_path / "copy.db"
        db.write_bytes(z.read(f"{cid}/case.db"))
    import sqlite3
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] > 0
