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

### Changed
- EVTX parsing uses the Rust `evtx` parser (python-evtx kept as optional fallback).
- `atad net` records an internal `--target` in the case scope automatically;
  public targets still need `--allow-public`.
- DNS lookups no longer require scope (they never contact the target).

### Removed
- OSQuery from `atad doctor` until it is used.
