"""Build a single-file atad executable and a release package.

    python packaging/build.py

Produces, in ``dist/``:

    atad.exe (or atad on Linux)
    atad-<version>-<os>-<arch>.zip   executable + rules/ + README + CHANGELOG
    SHA256SUMS.txt                    hashes of everything published

Like other incident-response tools, the rules folder ships next to the
executable (not inside it) so it can be updated without rebuilding.
Run this on the target OS: PyInstaller does not cross-compile.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BUILD = ROOT / "build"


def version() -> str:
    sys.path.insert(0, str(ROOT / "src"))
    from atad import __version__

    return __version__


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ver = version()
    os_name = {"win32": "windows", "linux": "linux", "darwin": "macos"}.get(sys.platform, sys.platform)
    arch = platform.machine().lower().replace("amd64", "x86_64")
    exe_name = "atad.exe" if os_name == "windows" else "atad"

    shutil.rmtree(BUILD, ignore_errors=True)
    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--console", "--clean", "--noconfirm",
        "--name", "atad",
        "--distpath", str(DIST), "--workpath", str(BUILD), "--specpath", str(BUILD),
        "--paths", str(ROOT / "src"),
        "--collect-data", "atad",            # schema.sql
        "--collect-submodules", "atad",
        "--hidden-import", "evtx",
        "--hidden-import", "jinja2", "--collect-submodules", "jinja2",
    ]
    # Package metadata lets `atad doctor` report real library versions.
    for dist in ("psutil", "evtx", "jinja2", "pydantic", "typer", "PyYAML"):
        args += ["--copy-metadata", dist]
    try:
        import yara  # noqa: F401
        args += ["--collect-binaries", "yara", "--hidden-import", "yara",
                 "--copy-metadata", "yara-python"]
    except ImportError:
        print("note: yara-python not installed — the executable will report YARA as unavailable")
    args.append(str(ROOT / "packaging" / "atad_entry.py"))
    subprocess.run(args, check=True)

    exe = DIST / exe_name
    package = DIST / f"atad-{ver}-{os_name}-{arch}.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(exe, f"atad/{exe_name}")
        for name in ("README.md", "CHANGELOG.md", "LICENSE", "LICENSE.ar"):
            if (ROOT / name).exists():
                z.write(ROOT / name, f"atad/{name}")
        for rule in sorted((ROOT / "rules").rglob("*")):
            if rule.is_file():
                z.write(rule, f"atad/{rule.relative_to(ROOT).as_posix()}")

    sums = DIST / "SHA256SUMS.txt"
    sums.write_text(
        "".join(f"{sha256(p)}  {p.name}\n" for p in (exe, package)), encoding="utf-8"
    )
    print(f"\nbuilt {exe}\n      {package}\n      {sums}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
