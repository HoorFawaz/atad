# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

import json
import os
import sys
from pathlib import Path

import pytest

from atad.core.exceptions import ValidationError
from atad.evidence.integrity import sha256_file
from atad.evidence.models import CollectionMode, ExecutionStatus
from atad.modules.checks import select_checks
from atad.modules.files import collector as fc
from atad.modules.files.runner import run_files

RULES = Path(__file__).resolve().parents[2] / "rules"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABC_MD5 = "900150983cd24fb0d6963f7d28e17f72"

needs_yara = pytest.mark.skipif(
    __import__("importlib").util.find_spec("yara") is None, reason="yara-python not installed"
)


@pytest.fixture
def evidence_dir(tmp_path):
    d = tmp_path / "evidence"
    (d / "sub").mkdir(parents=True)
    (d / "abc.txt").write_bytes(b"abc")
    (d / "invoice.pdf.exe").write_bytes(b"MZ\x90\x00 ATAD-DEMO-SIMULATED-DROPPER")
    (d / "report.pdf").write_bytes(b"MZ\x90\x00 pe hidden as pdf")
    (d / "real.pdf").write_bytes(b"%PDF-1.7 fine")
    (d / "sub" / "run.bat").write_bytes(b"powershell -EncodedCommand SQBFAFgA")
    return d


# ------------------------------------------------------------------ selection


def test_select_checks():
    assert select_checks(["hash", "info", "scan"]).selected == ["hash", "info", "scan"]
    s = select_checks(["hash", "info", "scan"], only="scan, hash")
    assert s.selected == ["hash", "scan"] and s.excluded == ["info"]
    s = select_checks(["hash", "info", "scan"], skip="info")
    assert s.selected == ["hash", "scan"] and s.excluded == ["info"]


@pytest.mark.parametrize("only,skip", [("hash", "info"), ("nope", None), (None, "x"),
                                       (",", None), (None, "hash,info,scan")])
def test_select_checks_errors(only, skip):
    with pytest.raises(ValidationError):
        select_checks(["hash", "info", "scan"], only, skip)


# -------------------------------------------------------------------- walking


def test_walk_sorted_and_limited(evidence_dir):
    w = fc.walk_files(evidence_dir)
    names = [p.name for p in w.files]
    assert names == ["abc.txt", "invoice.pdf.exe", "real.pdf", "report.pdf", "run.bat"]
    w = fc.walk_files(evidence_dir, max_files=2)
    assert len(w.files) == 2 and w.truncated


@pytest.mark.skipif(sys.platform.startswith("win"), reason="symlinks need privileges on Windows")
def test_symlinks_not_followed(evidence_dir, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    os.symlink(outside, evidence_dir / "linkdir")
    os.symlink(outside / "secret.txt", evidence_dir / "linkfile")
    w = fc.walk_files(evidence_dir)
    assert all("secret" not in str(p) for p in w.files)
    assert {p.name for p in w.links} == {"linkdir", "linkfile"}


def test_excluded_folder_not_walked(evidence_dir):
    w = fc.walk_files(evidence_dir, exclude=(evidence_dir / "sub",))
    assert "run.bat" not in [p.name for p in w.files]


# -------------------------------------------------------------------- hashing


def test_known_hashes(evidence_dir):
    h = fc.hash_file(evidence_dir / "abc.txt")
    assert h == {"sha256": ABC_SHA256, "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
                 "md5": ABC_MD5, "size": 3}


def test_files_not_modified(evidence_dir):
    target = evidence_dir / "abc.txt"
    before = (target.read_bytes(), os.stat(target).st_mtime_ns)
    fc.collect_hashes(evidence_dir)
    fc.collect_info(evidence_dir)
    assert (target.read_bytes(), os.stat(target).st_mtime_ns) == before


# ----------------------------------------------------------------- type & info


@pytest.mark.parametrize("head,label", [
    (b"MZ\x90\x00", "PE executable (Windows)"),
    (b"\x7fELF\x02", "ELF executable (Linux)"),
    (b"%PDF-1.4", "PDF document"),
    (b"PK\x03\x04", "ZIP / Office Open XML"),
    (b"just text\n", "Text"),
    (b"\x00\x01\x02\xff", "Unknown / data"),
])
def test_detect_type(head, label):
    assert fc.detect_type(head)[0] == label


def test_extension_mismatch_and_double_extension(evidence_dir):
    by_name = {r["name"]: r for r in fc.collect_info(evidence_dir)["records"]}
    assert any("does not match content" in x for x in by_name["report.pdf"]["suspicious_reasons"])
    assert any("double extension" in x for x in by_name["invoice.pdf.exe"]["suspicious_reasons"])
    assert by_name["real.pdf"]["suspicious_reasons"] == []
    assert by_name["abc.txt"]["suspicious_reasons"] == []
    assert by_name["abc.txt"]["modified_utc"].endswith("+00:00")


# ----------------------------------------------------------------------- YARA


@needs_yara
def test_yara_matches(evidence_dir):
    cap = fc.collect_yara(evidence_dir, fc.find_rule_files(RULES))
    hits = {Path(r["path"]).name: [m["rule"] for m in r["matches"]]
            for r in cap["records"] if r.get("matches")}
    assert hits == {
        "invoice.pdf.exe": ["ATAD_Demo_Simulated_Dropper"],
        "run.bat": ["ATAD_Demo_Encoded_PowerShell"],
    }


@needs_yara
def test_yara_bad_rule_raises(tmp_path, evidence_dir):
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken { condition: }")
    import yara

    with pytest.raises(yara.Error):
        fc.collect_yara(evidence_dir, [bad])


@needs_yara
def test_yara_skips_large_files(evidence_dir):
    cap = fc.collect_yara(evidence_dir, fc.find_rule_files(RULES), max_scan_bytes=10)
    assert any("skipped" in r for r in cap["records"])


# --------------------------------------------------------------------- runner


@needs_yara
def test_run_all_checks_local(case, evidence_dir):
    r = run_files(case, evidence_dir, ["hash", "info", "scan"], rules=RULES)
    assert [o.check for o in r.outcomes] == ["hash", "info", "scan"]
    assert all(o.execution.status is ExecutionStatus.SUCCESS for o in r.outcomes)
    assert r.collection_mode is CollectionMode.LOCAL

    # every evidence points to a raw capture whose hash still matches
    for e in r.evidence:
        assert e.raw_ref and sha256_file(case.path / e.raw_ref) == e.raw_sha256
        assert e.simulated is True  # the fixture case is simulated

    yara_hits = [e for e in r.evidence if e.kind.value == "yara_match"]
    assert len(yara_hits) == 2

    # same file linked across checks by its observables
    exe = str(evidence_dir / "invoice.pdf.exe")
    from atad.evidence.models import Observable
    linked = case.repo.find_evidence_by_observable(Observable(type="path", value=exe))
    kinds = sorted(case.repo.get_evidence(i).source_tool for i in linked)
    assert kinds == ["hashlib", "os.stat", "yara-python"]


def test_only_and_import_mode(case, evidence_dir):
    r = run_files(case, evidence_dir, ["hash"], excluded=["info", "scan"], source_host="WS-07")
    statuses = {o.check: (o.execution.status, o.execution.error) for o in r.outcomes}
    assert statuses["hash"][0] is ExecutionStatus.SUCCESS
    assert statuses["info"] == (ExecutionStatus.SKIPPED, "excluded_by_user")
    assert statuses["scan"] == (ExecutionStatus.SKIPPED, "excluded_by_user")
    assert all(e.host == "WS-07" and e.host_declared for e in r.evidence)
    assert all(e.collection_mode is CollectionMode.IMPORT for e in r.evidence)


def test_scan_without_rules_is_unavailable_not_clean(case, evidence_dir, tmp_path):
    r = run_files(case, evidence_dir, ["scan"], rules=tmp_path / "no-rules")
    o = r.outcome("scan")
    assert o.execution.status is ExecutionStatus.UNAVAILABLE
    assert o.evidence == []


def test_scan_without_yara_is_unavailable(case, evidence_dir, monkeypatch):
    from atad.adapters.base import ToolInfo
    monkeypatch.setattr(
        "atad.modules.files.runner.YaraPython.detect",
        lambda self: ToolInfo(name="yara", available=False, reason="pip install yara-python"),
    )
    r = run_files(case, evidence_dir, ["hash", "scan"], rules=RULES)
    assert r.outcome("hash").execution.status is ExecutionStatus.SUCCESS
    assert r.outcome("scan").execution.status is ExecutionStatus.UNAVAILABLE


@needs_yara
def test_bad_rules_recorded_as_failed_and_others_continue(case, evidence_dir, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yar").write_text("rule broken { condition: }")
    r = run_files(case, evidence_dir, ["hash", "scan"], rules=rules)
    assert r.outcome("hash").execution.status is ExecutionStatus.SUCCESS
    assert r.outcome("scan").execution.status is ExecutionStatus.FAILED
    assert "rror" in r.outcome("scan").execution.error


def test_cases_folder_inside_scanned_path_is_ignored(tmp_path):
    from atad.cases.manager import CaseManager
    root = tmp_path / "work"
    root.mkdir()
    (root / "a.txt").write_text("a")
    oc = CaseManager(root / "cases").create_case("self-scan")
    r = run_files(oc, root, ["hash"])
    assert [Path(x["path"]).name for x in r.outcome("hash").capture["records"]] == ["a.txt"]


def test_unreadable_file_becomes_error_evidence(case, evidence_dir):
    if sys.platform.startswith("win") or os.geteuid() == 0:
        pytest.skip("permission test needs a non-root POSIX user")
    locked = evidence_dir / "locked.bin"
    locked.write_bytes(b"x")
    locked.chmod(0)
    r = run_files(case, evidence_dir, ["hash"])
    errs = [e for e in r.evidence if e.status.value == "error"]
    assert len(errs) == 1 and "locked.bin" in errs[0].summary


def test_raw_capture_is_json(case, evidence_dir):
    r = run_files(case, evidence_dir, ["info"])
    raw = json.loads((case.path / r.outcome("info").execution.raw_ref).read_text(encoding="utf-8"))
    assert raw["check"] == "info" and raw["files_seen"] == 5


# ------------------------------------------------- one read for hash + YARA


@needs_yara
def test_hash_and_scan_together_match_separate_passes(evidence_dir):
    rules = fc.find_rule_files(RULES)
    hashes = fc.collect_hashes(evidence_dir)
    scans = fc.collect_yara(evidence_dir, rules)
    h2, s2 = fc.collect_hash_and_scan(evidence_dir, rules)
    assert h2["records"] == hashes["records"]
    assert s2["records"] == scans["records"]
    assert s2["read_once_with"] == "hash"


@needs_yara
def test_big_files_are_hashed_but_not_kept_for_yara(tmp_path):
    (tmp_path / "big.bin").write_bytes(b"x" * 5000)
    (tmp_path / "small.txt").write_text("ATAD-DEMO-SIMULATED-DROPPER")
    h, s = fc.collect_hash_and_scan(tmp_path, fc.find_rule_files(RULES), max_scan_bytes=1000)
    assert {r["path"].split("/")[-1].split("\\")[-1]: r.get("size") for r in h["records"]} == \
        {"big.bin": 5000, "small.txt": 27}
    by = {r["path"].split("/")[-1].split("\\")[-1]: r for r in s["records"]}
    assert "skipped" in by["big.bin"] and by["small.txt"]["matches"]


@needs_yara
def test_runner_reads_each_file_once(case, evidence_dir, monkeypatch):
    opened = []
    real_open = open

    def counting_open(file, *a, **k):
        opened.append(str(file))
        return real_open(file, *a, **k)
    monkeypatch.setattr(fc, "open", counting_open, raising=False)
    r = run_files(case, evidence_dir, ["hash", "scan"], excluded=["info"], rules=RULES)
    assert {o.execution.status for o in r.outcomes if o.check != "info"} == {ExecutionStatus.SUCCESS}
    files = set(opened)
    assert len(opened) == len(files)                     # no file opened twice
    scan = r.outcome("scan")
    assert scan.capture["read_once_with"] == "hash" and scan.evidence
