# Changelog

All notable changes to atad are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- `atad net --ports` is checked before anything runs, also when Nmap is not installed.

### Added
- `atad` without a command shows a welcome screen: the name in block letters (English and Arabic)
  and the commands to start with. Terminal only; `ATAD_NO_BANNER=1` turns the drawing off.
- Risk register (`docs/risks.md`): 18 rated risks with their controls and the tests that check them.
- README rewritten with screenshots of real ATAD output.
- Joint ownership by the ATAD Team (Hoor Fawaz and Danah Fawaz) in the license, file headers,
  README, NOTICE, TRADEMARKS and the report footer.
- Case management, evidence model and per-case SQLite database (M1).
- Safe execution engine, tool adapters and `atad doctor` (M2).
- `atad files`: SHA-256/MD5, metadata, real file type, YARA scanning (M3).
- `atad log`: Security and Sysmon EVTX import, live export, search (M4).
- `atad host` and `atad net`: processes, connections, users, startup; ping, Nmap, DNS (M5).
- Single-file executable build, release package with rules and SHA256SUMS, GitHub Actions
  (tests on Windows and Linux, Python 3.11–3.13, plus a ruff lint job).
- `--max-files`, `--max-events`, `--max-hosts` options.
- License: ATAD Source-Available License 1.0 (Arabic text official).
- `atad ioc load|list|check`: IOC lists (.txt / .csv, defanged values, CIDR ranges),
  copied into the case and hashed (M6).
- `atad correlate`, `atad findings`, `atad timeline`: rules IOC, YARA, S1, S2, R1–R5
  with a plain-language reason for every finding, configurable thresholds, and a
  rebuilt UTC timeline (M6).
- R1 also reports password guessing that did not succeed (medium), and a long attack
  is reported once instead of in pieces.
- R4 also links a finding's indicator to a different kind of event from the same
  source (lower confidence), and says which kind of link each one is.
- R4 confidence also depends on the indicator: a shared hash counts more than a
  shared IP address, domain or path (basis documented in docs/architecture.md §7).
- `atad report`: self-contained HTML report and JSON report from the same data, with
  findings linked to evidence, coverage of every check, and a fresh integrity check of
  every raw file (exit code 4 when one changed or is missing) (M7).
- HTML report laid out as a formal investigation report: document control table,
  executive summary, numbered sections, evidence integrity, coverage and limitations,
  appendices and reviewer sign-off; TLP 2.0 classification (`--tlp`).
- `atad export timeline` (CSV / JSONL with Timesketch fields) and `atad export case`
  (case zip with SHA256SUMS.txt) (M7).
- `atad triage` with profiles soc / dfir / full: runs the modules on this machine,
  then correlates, reports and (dfir/full) exports; `--only` / `--skip` by module (M8).
- `atad demo`: built-in SIMULATED scenario with decoys, loaded through the real parsers,
  with precision / recall per rule saved as JSON (M8).
- R4 links within one source only between timed events, not between two records of
  the same object (e.g. a file's hash record and its YARA match).
- Rule S3: suspicious auto-start entry (Windows Run key, Startup folder, service; Linux
  systemd, cron, rc.local, shell files, authorized_keys) that runs a program from a
  user-writable folder or downloads code; medium severity, low confidence.
- Linux (M9): `atad log` reads auth.log/secure, the systemd journal and auditd
  (live and import, format detected by content); `atad host startup` reads systemd,
  cron, rc.local, risky shell start-up lines and authorized_keys; routes with
  `ip -j route`; extra DNS records with `dig`; Linux tools in `atad doctor`.
- Sigma rules (M10): `atad correlate --sigma PATH` runs Sigma rules (conditions,
  modifiers incl. windash, base64offset, re, cidr, fieldref) mapped to Sysmon,
  Security, live host and Linux evidence; three ATAD rules in rules/sigma.
- R1 counts a logon that appears in both auth.log and the journal once.
- `atad files`: the folder is listed once, and when hash and YARA both run each file is
  read once for both (half the disk reading on big folders; same records as before).
- S2 flags only disguised programs (a program behind a document/image/media extension, or
  a runnable double extension); other type mismatches become a note. Found on a real
  laptop: 31 harmless files (.pages, .nupkg, .xpi, Git/npm scripts, .node addons) were flagged.
- The demo YARA rules no longer run in real scans unless given with `--rules`.
- `atad doctor` in the single-file build says Python is built in and does not suggest
  `pip install` for libraries that are not included.
- Progress counter for long steps (listing, hashing, YARA, processes, log records, Sigma
  rules), and a line naming each triage stage, shown only in a terminal; `ATAD_NO_PROGRESS=1`
  turns them off.
- Auto-start entries: shortcuts (.lnk) are read with a [MS-SHLLINK] parser and judged by
  the program they start, and unquoted paths with spaces are resolved the way Windows does
  (found on a real Windows 11 laptop: Webex Run key and Office "Send to OneNote" were
  wrongly flagged).
- SHA-1 is now computed for files and read from Sysmon hashes.
- NOTICE with third-party licenses (full texts shipped in every release), TRADEMARKS.md,
  and a copyright / SPDX line in every source file.

### Changed
- EVTX parsing uses the Rust `evtx` parser (python-evtx kept as optional fallback).
- `atad net` records an internal `--target` in the case scope automatically;
  public targets still need `--allow-public`.
- DNS lookups no longer require scope (they never contact the target).

### Removed
- OSQuery from `atad doctor` until it is used.
