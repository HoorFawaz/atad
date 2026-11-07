# Changelog

All notable changes to atad are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Case management, evidence model and per-case SQLite database (M1).
- Safe execution engine, tool adapters and `atad doctor` (M2).
- `atad files`: SHA-256/MD5, metadata, real file type, YARA scanning (M3).
- `atad log`: Security and Sysmon EVTX import, live export, search (M4).
- `atad host` and `atad net`: processes, connections, users, startup; ping, Nmap, DNS (M5).
- Single-file executable build, release package with rules and SHA256SUMS, GitHub Actions.
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
- Rule S3: auto-start entry (Run key, Startup folder, service) that runs a program from a
  user-writable folder — MITRE ATT&CK T1547.001 / T1543.003; medium severity, low confidence.
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
