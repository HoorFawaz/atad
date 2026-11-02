"""File evidence collection: hashing, metadata and YARA scanning.

Everything here is read-only: files are opened with ``rb`` only, symbolic
links and junctions are recorded but never followed, and nothing is ever
executed, moved, renamed or deleted.

Each ``collect_*`` function returns a JSON-serializable dict (the raw
capture saved in the case's ``raw/`` folder). The matching ``*_to_evidence``
function turns that capture into normalized evidence records.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from atad.adapters.base import ParseContext
from atad.evidence.models import (
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    Observable,
    SourceModule,
)

_CHUNK = 1024 * 1024

DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_SCAN_BYTES = 100 * 1024 * 1024      # YARA: skip files above 100 MiB
DEFAULT_YARA_TIMEOUT = 60                       # seconds per file

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4


# --------------------------------------------------------------------------- #
# Walking
# --------------------------------------------------------------------------- #


@dataclass
class WalkResult:
    files: list[Path]
    links: list[Path]          # symlinks / junctions seen but not followed
    errors: list[dict]         # folders that could not be listed
    truncated: bool            # stopped at max_files


def walk_files(
    root: Path, max_files: int = DEFAULT_MAX_FILES, exclude: tuple[Path, ...] = ()
) -> WalkResult:
    """List regular files under ``root`` (or ``root`` itself), never following links.

    Folders in ``exclude`` (e.g. atad's own cases folder) are not entered, so
    atad never collects its own output as evidence.
    """
    files: list[Path] = []
    links: list[Path] = []
    errors: list[dict] = []
    excluded = {_real(p) for p in exclude}

    if root.is_symlink() or _is_junction(root):
        return WalkResult([], [root], [], False)
    if root.is_file():
        return WalkResult([root], [], [], False)

    def onerror(exc: OSError) -> None:
        errors.append({"path": str(exc.filename), "error": exc.strerror or str(exc)})

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
        here = Path(dirpath)
        # Do not descend into linked folders.
        for d in list(dirnames):
            p = here / d
            if p.is_symlink() or _is_junction(p):
                links.append(p)
                dirnames.remove(d)
            elif excluded and _real(p) in excluded:
                dirnames.remove(d)
        dirnames.sort()
        for name in sorted(filenames):
            p = here / name
            if p.is_symlink():
                links.append(p)
                continue
            if len(files) >= max_files:
                return WalkResult(files, links, errors, True)
            files.append(p)
    return WalkResult(files, links, errors, False)


def _real(p: Path) -> str:
    try:
        return os.path.normcase(str(p.resolve()))
    except OSError:
        return os.path.normcase(str(p.absolute()))


def _is_junction(p: Path) -> bool:
    is_junction = getattr(os.path, "isjunction", None)  # Python 3.12+
    try:
        return bool(is_junction and is_junction(p))
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #


def hash_file(path: Path) -> dict[str, Any]:
    # MD5 is kept only to match IOC lists that still publish MD5 hashes.
    sha256, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest(), "size": size}


def collect_hashes(
    root: Path, max_files: int = DEFAULT_MAX_FILES, exclude: tuple[Path, ...] = ()
) -> dict[str, Any]:
    walk = walk_files(root, max_files, exclude)
    records = []
    for p in walk.files:
        try:
            records.append({"path": str(p), **hash_file(p)})
        except OSError as exc:
            records.append({"path": str(p), "error": exc.strerror or str(exc)})
    return _capture("hash", root, walk, records)


# --------------------------------------------------------------------------- #
# Metadata & type
# --------------------------------------------------------------------------- #

# (magic bytes, offset, type label, typical extensions)
_SIGNATURES: list[tuple[bytes, int, str, tuple[str, ...]]] = [
    (b"MZ", 0, "PE executable (Windows)", (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi", ".com")),
    (b"\x7fELF", 0, "ELF executable (Linux)", (".so", ".elf", ".bin", ".o", "")),
    (b"%PDF", 0, "PDF document", (".pdf",)),
    (b"PK\x03\x04", 0, "ZIP / Office Open XML", (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".msix")),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE compound file (old Office / MSI)", (".doc", ".xls", ".ppt", ".msi", ".msg")),
    (b"Rar!\x1a\x07", 0, "RAR archive", (".rar",)),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", (".7z",)),
    (b"\x1f\x8b", 0, "GZIP archive", (".gz", ".tgz")),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", (".png",)),
    (b"\xff\xd8\xff", 0, "JPEG image", (".jpg", ".jpeg")),
    (b"GIF8", 0, "GIF image", (".gif",)),
    (b"ElfFile\x00", 0, "Windows event log (EVTX)", (".evtx",)),
    (b"#!", 0, "Script with interpreter line", (".sh", ".py", ".pl", "")),
]

# Extensions that look harmless to a user; a PE behind them is a classic trick.
_DOCUMENT_LIKE = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
                  ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".csv"}


def detect_type(head: bytes) -> tuple[str, tuple[str, ...]]:
    for magic, offset, label, exts in _SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            return label, exts
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head[:512]):
        return "Text", ()
    return "Unknown / data", ()


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def file_info(path: Path) -> dict[str, Any]:
    st = path.stat(follow_symlinks=False)
    with open(path, "rb") as fh:
        head = fh.read(4096)
    label, typical_exts = detect_type(head)
    ext = path.suffix.lower()
    name = path.name
    # Double extension like "invoice.pdf.exe"
    parts = name.lower().split(".")
    double_ext = len(parts) >= 3 and f".{parts[-2]}" in _DOCUMENT_LIKE

    info: dict[str, Any] = {
        "path": str(path),
        "name": name,
        "extension": ext,
        "size": st.st_size,
        "type": label,
        "modified_utc": _utc(st.st_mtime),
        "accessed_utc": _utc(st.st_atime),
    }
    birth = getattr(st, "st_birthtime", None)
    if birth is not None:
        info["created_utc"] = _utc(birth)
    elif sys.platform.startswith("win"):
        info["created_utc"] = _utc(st.st_ctime)  # st_ctime is creation time on Windows
    else:
        info["metadata_changed_utc"] = _utc(st.st_ctime)

    attrs = getattr(st, "st_file_attributes", None)
    if attrs is not None:
        info["hidden"] = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
        info["system"] = bool(attrs & FILE_ATTRIBUTE_SYSTEM)
    else:
        info["hidden"] = name.startswith(".")
    info["executable_bit"] = bool(st.st_mode & stat.S_IXUSR) if not sys.platform.startswith("win") else None

    reasons: list[str] = []
    if typical_exts and ext not in typical_exts:
        reasons.append(f"extension '{ext or '(none)'}' does not match content ({label})")
    if label.startswith("PE executable") and double_ext:
        reasons.append(f"executable with double extension '{name}'")
    info["suspicious_reasons"] = reasons
    return info


def collect_info(
    root: Path, max_files: int = DEFAULT_MAX_FILES, exclude: tuple[Path, ...] = ()
) -> dict[str, Any]:
    walk = walk_files(root, max_files, exclude)
    records = []
    for p in walk.files:
        try:
            records.append(file_info(p))
        except OSError as exc:
            records.append({"path": str(p), "error": exc.strerror or str(exc)})
    return _capture("info", root, walk, records)


# --------------------------------------------------------------------------- #
# YARA
# --------------------------------------------------------------------------- #

YARA_EXTENSIONS = (".yar", ".yara")


def find_rule_files(rules: Path) -> list[Path]:
    if rules.is_file():
        return [rules]
    if rules.is_dir():
        return sorted(p for p in rules.rglob("*") if p.suffix.lower() in YARA_EXTENSIONS and p.is_file())
    return []


def compile_rules(rule_files: list[Path]) -> Any:
    """Compile YARA rules. Raises ImportError if yara-python is missing,
    or ``yara.SyntaxError`` for bad rules."""
    import yara  # optional dependency

    # Namespace per file so rules with the same name in two files don't clash.
    sources = {f"ns{i}_{p.stem}": str(p) for i, p in enumerate(rule_files)}
    # Externals/includes disabled: rules cannot pull in other files.
    return yara.compile(filepaths=sources, includes=False)


def collect_yara(
    root: Path,
    rule_files: list[Path],
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    timeout: int = DEFAULT_YARA_TIMEOUT,
    exclude: tuple[Path, ...] = (),
) -> dict[str, Any]:
    compiled = compile_rules(rule_files)
    walk = walk_files(root, max_files, exclude)
    records = []
    for p in walk.files:
        try:
            size = p.stat(follow_symlinks=False).st_size
            if size > max_scan_bytes:
                records.append({"path": str(p), "skipped": f"larger than {max_scan_bytes} bytes"})
                continue
            with open(p, "rb") as fh:
                data = fh.read()
            matches = compiled.match(data=data, timeout=timeout)
        except OSError as exc:
            records.append({"path": str(p), "error": exc.strerror or str(exc)})
            continue
        except Exception as exc:  # yara.TimeoutError / yara.Error
            records.append({"path": str(p), "error": f"yara: {exc}"})
            continue
        records.append({
            "path": str(p),
            "sha256": hashlib.sha256(data).hexdigest(),
            "matches": [
                {
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "meta": {k: str(v) for k, v in m.meta.items()},
                    "strings": sorted({s.identifier for s in m.strings}),
                }
                for m in matches
            ],
        })
    cap = _capture("scan", root, walk, records)
    cap["rule_files"] = [str(p) for p in rule_files]
    return cap


# --------------------------------------------------------------------------- #
# Capture helpers & evidence mapping
# --------------------------------------------------------------------------- #


def _capture(check: str, root: Path, walk: WalkResult, records: list[dict]) -> dict[str, Any]:
    return {
        "check": check,
        "root": str(root),
        "files_seen": len(walk.files),
        "truncated": walk.truncated,
        "links_not_followed": [str(p) for p in walk.links],
        "walk_errors": walk.errors,
        "records": records,
    }


def _base(ctx: ParseContext, tool: str) -> dict[str, Any]:
    return dict(
        case_id=ctx.case_id,
        source_module=SourceModule.FILES,
        source_tool=tool,
        tool_version=ctx.tool_version,
        collection_mode=ctx.collection_mode,
        host=ctx.host,
        host_declared=ctx.host_declared,
        execution_id=ctx.execution_id,
        raw_ref=ctx.raw_ref,
        raw_sha256=ctx.raw_sha256,
        simulated=ctx.simulated,
    )


def _error_evidence(rec: dict, ctx: ParseContext, tool: str) -> Evidence:
    return Evidence(
        **_base(ctx, tool),
        kind=EvidenceKind.FILE,
        summary=f"could not read {rec['path']}: {rec['error']}",
        data=rec,
        observables=[Observable(type="path", value=rec["path"])],
        status=EvidenceStatus.ERROR,
    )


def hashes_to_evidence(capture: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for rec in capture["records"]:
        if "error" in rec:
            out.append(_error_evidence(rec, ctx, "hashlib"))
            continue
        out.append(Evidence(
            **_base(ctx, "hashlib"),
            kind=EvidenceKind.FILE,
            summary=f"SHA-256 {rec['sha256'][:16]}… {Path(rec['path']).name}",
            data=rec,
            observables=[
                Observable(type="path", value=rec["path"]),
                Observable(type="sha256", value=rec["sha256"]),
                Observable(type="md5", value=rec["md5"]),
            ],
        ))
    return out


def info_to_evidence(capture: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for rec in capture["records"]:
        if "error" in rec:
            out.append(_error_evidence(rec, ctx, "os.stat"))
            continue
        flag = " — SUSPICIOUS: " + "; ".join(rec["suspicious_reasons"]) if rec["suspicious_reasons"] else ""
        out.append(Evidence(
            **_base(ctx, "os.stat"),
            kind=EvidenceKind.FILE,
            event_time=datetime.fromisoformat(rec["modified_utc"]),
            summary=f"{rec['name']} ({rec['type']}, {rec['size']} bytes){flag}",
            data=rec,
            observables=[Observable(type="path", value=rec["path"])],
        ))
    return out


def yara_to_evidence(capture: dict, ctx: ParseContext) -> list[Evidence]:
    """One evidence per matched rule. Files without matches produce none;
    the raw capture still lists every scanned file as proof of coverage."""
    out = []
    for rec in capture["records"]:
        if "error" in rec:
            out.append(_error_evidence(rec, ctx, "yara-python"))
            continue
        for m in rec.get("matches", []):
            out.append(Evidence(
                **_base(ctx, "yara-python"),
                kind=EvidenceKind.YARA_MATCH,
                summary=f"YARA rule '{m['rule']}' matched {Path(rec['path']).name}",
                data={"path": rec["path"], "sha256": rec["sha256"], **m},
                observables=[
                    Observable(type="path", value=rec["path"]),
                    Observable(type="sha256", value=rec["sha256"]),
                ],
            ))
    return out


def iter_suspicious(capture: dict) -> Iterator[dict]:
    for rec in capture.get("records", []):
        if rec.get("suspicious_reasons"):
            yield rec
