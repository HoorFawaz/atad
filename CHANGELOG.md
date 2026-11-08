# Changelog

All notable changes to ATAD are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-11-08

First release.

### Cases and evidence
- Case management, a normalized evidence model and one SQLite database per case.
- Safe execution engine: tools run with argument lists, time limits and output caps;
  every raw output is kept read-only with its SHA-256, command and tool version.
- Collection modes `local`, `import` and `network`; every record states which one.
- Authorized network scope per case; public targets need `--allow-public`.
- `atad doctor`: installed tools, versions and admin rights, also in the single-file build.

### Collection modules
- `atad host`: processes, network connections, users and start-up entries.
  Windows: Run keys, Startup folder (shortcuts read with an [MS-SHLLINK] parser and judged by
  the program they start; unquoted paths resolved the way Windows does) and services.
  Linux: systemd units, cron, rc.local, shell start-up files and `authorized_keys`.
- `atad log`: Windows Security (4624, 4625, 4688, 4720) and Sysmon (1, 3, 11), live or from
  `.evtx` files, read with the Rust `evtx` parser. Linux auth.log / secure, systemd journal
  and auditd, live or imported, with the format detected from the content.
- `atad files`: SHA-256, SHA-1 and MD5, metadata, real file type and YARA. Each file is read
  once for hashing and YARA together.
- `atad net`: interfaces, ping, DNS and Nmap (TCP connect, no scripts); on Linux also routes
  and DNS records. Port lists are checked before anything runs.
- `atad ioc`: IP, CIDR range, domain, URL and hash lists (`.txt` / `.csv`, defanged values).
- `--max-files`, `--max-events` and `--max-hosts` limits.

### Correlation
- Rules IOC, YARA, S1 (encoded PowerShell), S2 (disguised programs), S3 (auto-start from a
  user-writable folder), R1 (repeated failed logons, with or without success), R2 (process
  to known indicator), R3 (flagged file executed), R4 (indicator in independent sources) and
  R5 (cluster of findings). Each finding states its reason and its evidence.
- Severity and confidence are separate. R4 confidence depends on source independence and
  indicator type; the basis is documented in docs/architecture.md §7.
- R1 counts a logon recorded by two logs once, and reports a long attack as one finding.
- Sigma rules (conditions and modifiers including windash, base64offset, re, cidr and
  fieldref) mapped to Sysmon, Security, host and Linux evidence; three ATAD rules included.
- Thresholds and disabled rules set in a YAML file; a UTC timeline rebuilt on every run.

### Reports and exports
- Formal HTML report and JSON report from the same data: document control, executive
  summary, findings with their basis, timeline, evidence integrity, coverage and
  limitations, appendices and sign-off; TLP 2.0 label (`--tlp`).
- Every raw file is hashed again when a report is written; a changed or missing file is
  flagged and the command exits with code 4.
- `atad export timeline` (CSV / JSONL with Timesketch fields, spreadsheet formulas blocked)
  and `atad export case` (case zip with SHA256SUMS.txt).

### Workflow
- `atad triage` with the profiles soc, dfir and full, and `--only` / `--skip` by module.
- `atad demo`: a simulated case with decoys, loaded through the real parsers and scored
  per rule (precision and recall saved as JSON). Demo YARA rules run only in the demo or
  with `--rules`.
- `atad` without a command shows a welcome screen with the name in block letters (English
  and Arabic) and the commands to start with; `ATAD_NO_BANNER=1` turns the drawing off.
- Progress counters and stage lines on long steps, in a terminal only (`ATAD_NO_PROGRESS=1`).

### Project
- ATAD Source-Available License 1.0 (Arabic text official), owned jointly by the ATAD Team
  (Hoor Fawaz and Danah Fawaz). NOTICE with third-party licenses, TRADEMARKS.md, and a
  copyright line in every source file.
- Single-file Windows executable and release package with rules and SHA256SUMS.
- GitHub Actions: tests on Windows and Linux with Python 3.11–3.13, and a lint job.
- Documentation: architecture, risk register and a README with screenshots of real output.
