# atad — Architecture & Design (v0.1)

> ATAD (عَتاد) — Advanced Toolkit for Attack & Defense.

---

## 1. Key decisions

| Decision | Choice | Reason |
|---|---|---|
| MVP platform | **Windows first** | Sysmon + EVTX give the richest evidence for the demo. Linux adapters come after the MVP; the design keeps them possible. |
| Where data is collected | **Local mode + Import mode** | Host, log and file evidence can only be collected from the machine atad runs on. |
| Meaning of `--target` | Network target only | It never changes where host/log/file data comes from. |
| Storage | SQLite per case + raw files on disk | Simple, portable, exportable. |
| Correlation | Explicit, named, testable rules | Every link must be explainable and measurable. |

### 1.1 Collection modes

| Mode | How | Evidence `host` field |
|---|---|---|
| `local` | atad runs **on the suspect machine** and collects from it | The real local hostname (detected, not user-typed) |
| `import` | Analyst imports files copied from the suspect machine (`--path`) | Value given with `--source-host`, marked as *analyst-declared* |
| `network` | Nmap / ping / DNS against an authorized `--target` | The scanned IP / hostname |

This removes the gap where a remote `--target` would have been labelled with
data that was actually collected from the analyst's own machine.

---

## 2. Architectural gaps & technical risks

| # | Gap / risk | Impact | Mitigation |
|---|---|---|---|
| 1 | `--target` mixed remote and local collection | Wrong evidence attribution | Collection modes (§1.1); every record stores `collection_mode` |
| 2 | Timestamps from different sources/timezones | False or missed correlations | Store all times as UTC-aware; keep original string in `data` |
| 3 | Admin rights needed (Security log, Sysmon log, some Nmap scans) | Silent partial results | Privilege check at start; recorded in execution log and report |
| 4 | Missing/unknown tool versions | Unreproducible results | `atad doctor` + version stored on every execution |
| 5 | "Unavailable" confused with "nothing found" | Misleading report | Execution status: `success`, `failed`, `skipped`, `unavailable`; report shows coverage |
| 6 | Vague correlation | False positives, not explainable | Rule catalogue (§7), each rule unit-tested on labelled data |
| 7 | PID reuse on Windows | Wrong process links | Prefer Sysmon `ProcessGuid`; PID + time window as fallback only |
| 8 | Large raw outputs | Slow DB / huge reports | Raw outputs as files with SHA-256; size limits on capture |
| 9 | Synthetic demo data confused with real | Credibility | `simulated` flag on case and evidence; shown in report |
| 10 | Command injection through arguments | Tool becomes an attack vector | Argument lists only, strict validation, no `shell=True` |

---

## 3. Integration realism (Windows MVP)

| Integration | How atad uses it | Realistic for MVP? | Dependency type |
|---|---|---|---|
| Nmap | `nmap -oX -` (XML), safe profiles only | Yes | Optional external |
| Ping / ipconfig / nslookup | Native, parsed output | Yes | Built-in OS |
| Processes / connections | `psutil` (Python) | Yes — more reliable than parsing `tasklist`/`netstat` | Mandatory Python |
| OSQuery | `osqueryi --json` | Possible, not needed for demo | Optional external (post-MVP) |
| Sysmon | Read its EVTX log (Event IDs 1, 3, 11) | Yes, if Sysmon is installed | Optional external |
| Windows Event Logs | Live: `wevtutil epl` → `.evtx` file; Import: `.evtx` files; parse with `python-evtx` | Yes, documented subset | Mandatory Python |
| YARA | `yara-python` (Windows wheels exist) | Yes | Optional Python extra |
| SHA-256 / file metadata | `hashlib`, `os.stat` | Yes | Built-in |
| Linux auth/syslog | Plain-text parsers | Post-MVP | — |

### Supported log subset (MVP)

| Source | Event IDs |
|---|---|
| Security | 4624 (logon success), 4625 (logon failure), 4688 (process created), 4720 (user created) |
| Sysmon | 1 (process create), 3 (network connection), 11 (file create) |

---

## 4. Implementation order

1. Evidence model + SQLite schema + case management *(foundation for everything)*
2. Safe execution engine + adapter base + `atad doctor`
3. FILE module (SHA-256, metadata, YARA) — easiest to test
4. LOG module (EVTX import, then live export)
5. HOST module (psutil) and NET module (Nmap)
6. IOC module (local lists)
7. Correlation engine + timeline
8. Reports (JSON, then HTML)
9. `atad triage` + profiles
10. Demo dataset + evaluation scripts

---

## 5. Normalized evidence model

```text
Evidence
├── id               EVD-000001 (unique per case)
├── case_id          CASE-001
├── kind             process | network_connection | open_port | logon | log_event |
│                    file | yara_match | ioc_match | host_info | interface | dns_record
├── source_module    net | host | files | log | ioc
├── source_tool      e.g. nmap, psutil, python-evtx, yara-python, hashlib
├── tool_version
├── collection_mode  local | import | network
├── host             hostname or IP the evidence is about
├── host_declared    true when the analyst typed the host (import mode)
├── collected_at     UTC, when atad collected it
├── event_time       UTC, when the event happened (may be null)
├── execution_id     link to the run that produced it
├── raw_ref          relative path to the raw output file in the case folder
├── raw_sha256       hash of that raw file
├── summary          one-line human description
├── data             source-specific fields (JSON)
├── observables      list of (type, value) — the correlation keys
├── simulated        true for synthetic/demo data
└── status           collected | partial | error
```

### Observables (correlation keys)

| Type | Normalization |
|---|---|
| `ip` | `ipaddress` canonical form |
| `domain` | lower-case, no trailing dot |
| `url` | stripped |
| `sha256` / `md5` | lower-case hex |
| `path` | Windows paths lower-cased, `/` → `\` |
| `user` | lower-case, `DOMAIN\user` kept |
| `hostname` | lower-case |
| `pid` | integer as text |
| `process_guid` | Sysmon GUID, lower-case |

### Findings

```text
Finding
├── id, case_id, title, description
├── category     observation | suspicious | correlated | hypothesis
├── severity     info | low | medium | high | critical
├── confidence   low | medium | high
├── rule_id      which rule produced it (null if manual)
├── rationale    plain-language reason the evidence was linked
└── evidence_ids linked evidence (many-to-many)
```

---

## 6. Database schema (SQLite, one DB per case)

| Table | Purpose |
|---|---|
| `meta` | schema version |
| `cases` | case id, name, profile, simulated flag, created time |
| `targets` | authorized network targets for this case (scope) |
| `executions` | every tool run: command, tool, version, start/end, status, exit code, raw file + hash, error |
| `tools` | detected tools and versions |
| `evidence` | normalized evidence records |
| `observables` | (evidence_id, type, value) — indexed for correlation |
| `findings` | findings |
| `finding_evidence` | links findings ↔ evidence |
| `iocs` | imported indicators (type, value, source, confidence) |
| `timeline_events` | ordered events built from evidence |
| `reports` | generated reports with path and hash |

The full SQL lives in `src/atad/cases/schema.sql`.

Case folder:

```text
cases/CASE-001/
├── case.db
├── raw/          original tool outputs (never edited)
├── normalized/   JSON exports of evidence
├── logs/         atad execution log
├── reports/
└── exports/
```

---

## 7. Correlation rule catalogue (MVP)

| Rule | Logic | Output category |
|---|---|---|
| R1 Brute force then success | ≥ 5 × 4625 then 4624 from the same source IP within 10 min | suspicious |
| R2 Process → IOC connection | Network connection (psutil / Sysmon 3) to an IP/domain in the IOC list, linked to its process | suspicious |
| R3 Malicious file executed | Process image SHA-256 = SHA-256 of a file with a YARA match | suspicious |
| R4 Indicator in many sources | Same IOC observable in ≥ 2 different modules | correlated |
| R5 Activity cluster | ≥ 3 suspicious items on the same host within 15 min | hypothesis |

Every rule result stores its `rationale` text, e.g.
*"5 failed logons from 10.0.0.66 between 10:02 and 10:05, then a successful logon for user bob at 10:06."*

Thresholds live in a config file so they are visible and adjustable.

---

## 8. Tool adapter interface

```python
class ToolAdapter(ABC):
    name: str
    supported_os: set[str]          # {"windows"}, {"windows", "linux"}

    def detect(self) -> ToolInfo: ...
        # available, version, path, reason_if_unavailable

    def build_command(self, **params) -> list[str]: ...
        # validated argument list, never a shell string

    def parse(self, raw: bytes, context: ParseContext) -> list[Evidence]: ...
        # pure function: raw output -> normalized evidence
```

Execution is **not** done by adapters. `core/execution.py` runs the command with:
argument list, timeout, output size cap, no shell, captured stdout/stderr,
raw output saved to `raw/` with SHA-256, and an `executions` row.
This keeps parsing testable with saved fixtures and no real tools.

Pure-Python sources (psutil, hashlib, python-evtx) use a `CollectorAdapter`
with `collect(context) -> RawCapture` instead of `build_command`, so their raw
data is still saved and hashed the same way.

---

## 9. CLI structure

### 9.1 Three levels of use

| Level | Example | What runs | Output |
|---|---|---|---|
| Whole module | `atad net --target 192.168.1.15` | Every check of the module | Module report |
| Chosen checks | `atad net --target 192.168.1.15 --only ping,scan` | Only the listed checks | Module report |
| | `atad net --target 192.168.1.15 --skip dns` | All checks except the listed ones | Module report |
| Single check | `atad net scan --target 192.168.1.15` | One check | Summary on screen + evidence stored |
| Everything | `atad triage --profile soc` | All modules + correlation | Full investigation report |

Rules for `--only` / `--skip`:

* Comma-separated check names; unknown names are rejected with the list of valid ones.
* `--only` and `--skip` cannot be used together.
* Checks left out by the analyst are recorded as `skipped` with reason
  `excluded_by_user`, and the report shows them as *not run by choice* — never as failures.
* Running a module without `--case` creates a new case automatically; its
  `--target` is validated and added to that case's scope (private ranges only
  unless `--allow-public`).

### 9.2 Checks per module

| Module | Checks | Default `--only` |
|---|---|---|
| `net` | `interfaces`, `ping`, `scan`, `dns` | all |
| `host` | `info`, `processes`, `connections`, `users`, `startup` | all |
| `files` | `hash`, `info`, `scan` | all |
| `log` | `security`, `sysmon` (local) — or `--path` for import | all available |

### 9.3 Full command list

```text
atad doctor                                        tool & privilege check
atad case new --name "..." [--profile soc] [--simulated]
atad case list | show CASE-001
atad scope add --case CASE-001 --target 192.168.1.15

atad net   [--only ...|--skip ...] --target ...  [--case ...]
atad net   interfaces | ping | scan | dns
atad host  [--only ...|--skip ...]               [--case ...]
atad host  info | processes | connections | users | startup
atad files [--only ...|--skip ...] --path ...    [--case ...]
atad files hash | info | scan --path ...
atad log   [--only ...|--skip ...]               [--case ...]   (local, live export)
atad log   import --path ... --source-host ...                 (import mode)
atad log   search --case ... --keyword ...
atad ioc   load --file iocs.txt --case ...
atad ioc   check --case ...
atad correlate --case ...
atad timeline  --case ...
atad report    --case ... --format html|json
atad triage [--target IP] --profile soc|dfir|full [--case ...]
```

Exit codes: `0` success, `1` error, `2` invalid input, `3` partial execution.

---

## 10. Dependencies

| Mandatory (pip) | Optional (pip extra) | Optional (external, detected) |
|---|---|---|
| typer, pydantic, pyyaml, jinja2, psutil, python-evtx | yara-python (`atad[yara]`) | nmap, sysmon, osquery |

The MVP must run with only the mandatory set; missing optional pieces are
reported as `unavailable`, never as an error that stops the run.

---

## 11. Roadmap & testable milestones

| Milestone | Delivers | Done when |
|---|---|---|
| M1 Foundation | Models, schema, case manager, scope validation, `atad case` | Unit tests pass; a case folder + DB is created and listed |
| M2 Execution | Safe runner, adapter base, `atad doctor` | Timeout, missing tool, output cap and injection tests pass |
| M3 Files | Hash, metadata, YARA | Known-hash and test-rule fixtures pass |
| M4 Logs | EVTX import + live export | Sample EVTX fixtures parse to expected evidence |
| M5 Host & Net | psutil collection, Nmap XML | Nmap XML fixture parses; local collection runs on Windows |
| M6 IOC & Correlation | IOC lists, rules R1–R5, timeline | Labelled dataset: precision/recall reported |
| M7 Reports | JSON + HTML | Report built from demo case; every finding links to evidence |
| M8 Triage & Demo | Profiles, `atad triage`, demo dataset, metrics | Full demo scenario runs end to end |
