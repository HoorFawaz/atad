# ATAD — Architecture & Design (v0.1)

> ATAD (عَتاد) — Advanced Toolkit for Attack & Defense.

---

## 1. Key decisions

| Decision | Choice | Reason |
|---|---|---|
| MVP platform | **Windows first, Linux next (M9)** | Sysmon + EVTX give the richest evidence for the demo. Linux follows as milestone M9 with Linux-native tools replacing the Windows-only ones (§3.1). |
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
| Nmap | `nmap -sT ... -oX -` (XML); profiles `quick` / `standard`, TCP connect, no scripts | Yes | Optional external |
| Ping | Native `ping`; reachable = exit code 0 **and** a `TTL=` reply line | Yes | Built-in OS |
| Interfaces | psutil (`net_if_addrs`, `net_if_stats`) | Yes | Mandatory Python |
| DNS | System resolver (`getaddrinfo`, `gethostbyaddr`), 10 s timeout | Yes | Built-in |
| Processes / connections | `psutil` (Python) | Yes — more reliable than parsing `tasklist`/`netstat` | Mandatory Python |
| OSQuery | Not used in the MVP (psutil covers the same data) | Post-MVP | — |
| Sysmon | Read its EVTX log (Event IDs 1, 3, 11) | Yes, if Sysmon is installed | Optional external |
| Windows Event Logs | Live: `wevtutil epl` → `.evtx` file; Import: `.evtx` files; parse with `evtx` (Rust) | Yes, documented subset | Mandatory Python |
| YARA | `yara-python` (Windows wheels exist) | Yes | Optional Python extra |
| SHA-256 / file metadata | `hashlib`, `os.stat` | Yes | Built-in |
| Linux auth/syslog | Plain-text parsers | Post-MVP | — |

**Why no `ipconfig` / `nslookup` parsing (decided in M5):** their text output
changes with the Windows display language (e.g. Arabic Windows), so parsing it
would break on real machines. psutil and the system resolver return the same
data in a structured form. For the same reason, ping is judged by the `TTL=`
marker and the exit code, not by English words such as "Reply from".

### Supported log subset (MVP)

| Source | Event IDs |
|---|---|
| Security | 4624 (logon success), 4625 (logon failure), 4688 (process created), 4720 (user created) |
| Sysmon | 1 (process create), 3 (network connection), 11 (file create) |

### 3.1 Linux equivalents (milestone M9)

Linux is not dropped: it is the next platform after the MVP. Every
Windows-only integration is replaced on Linux by the tool SOC/DFIR teams
normally use there. Modules, check names and the evidence model stay the
same; only the adapter changes.

| Purpose | Windows (MVP) | Linux (M9) |
|---|---|---|
| Network interfaces | psutil | psutil (+ `ip -j route` for routes) |
| DNS lookups | system resolver | system resolver (+ `dig` for record types) |
| Connectivity | `ping` | `ping` |
| Ports & services | Nmap | Nmap |
| Processes / connections | psutil | psutil (+ `ss -tunap` as fallback) |
| Endpoint queries | OSQuery (optional) | OSQuery (optional) |
| Process / network telemetry | Sysmon | auditd (`ausearch`) — or Sysmon for Linux if installed |
| System & security logs (live) | `wevtutil` export of Security log | `journalctl -o json` + `/var/log/auth.log` or `/var/log/secure` |
| Log file parsing | python-evtx (`.evtx`) | Python parsers for auth.log, syslog, journal JSON, audit.log |
| Persistence / startup | Run keys, Startup folders, auto-start services (scheduled tasks: post-MVP) | systemd units, cron, `/etc/rc.local`, shell profiles, `authorized_keys` |
| File hashing / YARA | hashlib / yara-python | hashlib / yara-python |

Linux log subset planned for M9:

| Source | Events |
|---|---|
| auth.log / secure | SSH accepted / failed logins, `sudo`, `useradd` |
| journal | sshd, sudo, systemd service start |
| auditd | `execve` (process), `connect` (network) |

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

Single-source rules (each turns one kind of suspicious evidence into a finding):

| Rule | Logic | Severity / confidence | Category |
|---|---|---|---|
| IOC Indicator seen | An observable equals a loaded indicator (IP, domain, URL host, hash) or an IP falls in a loaded CIDR range. The machine's own interface addresses are ignored | from the indicator's confidence | suspicious |
| YARA Rule matched | A `yara_match` record | the rule's `meta: severity`, else medium | suspicious |
| S1 Encoded PowerShell | Process command line with `-enc` / `-EncodedCommand` (and short forms) | medium / medium | suspicious |
| S2 Disguised file | File whose real type does not match its extension, or a double extension | medium / medium | suspicious |

Correlation rules (link evidence across events and sources):

| Rule | Logic | Severity / confidence | Category |
|---|---|---|---|
| R1 Brute force | ≥ 5 × 4625 from the same source IP on the same host within 10 min. Failures closer than 10 min apart form one burst, so a long attack is one finding. A 4624 from that IP during the burst or within 10 min after it → *then success* | with success: high / high; without: medium / high | suspicious |
| R2 Process → IOC connection | Network connection (psutil / Sysmon 3) to an IOC IP/domain/range, linked to its process by Sysmon ProcessGuid, else by PID + program path | high / indicator confidence | suspicious |
| R3 Flagged file executed | A process with the SHA-256 of a YARA-matched file (high confidence), or the same path when no hash exists (medium) | high | suspicious |
| R4 Indicator in other sources or events | A key indicator of a finding (IP, domain, hash, path) also appears in (a) evidence from a different module — *independent source*, or (b) the same module but a different kind of event — *same source, different event type* (e.g. the brute-force IP later contacted by a process, both from event logs). Within one source both records must be events with a time; repeats of the same kind of event, and two records of the same object (a file's hash record and its YARA match), are not links. Loopback and own addresses are skipped; links already made by another finding are not repeated | medium; confidence from the table below | correlated |
| R5 Activity cluster | ≥ 3 suspicious findings on the same host within 15 min (by event time) | highest of the group / medium | hypothesis |

**R4 confidence.** Two things decide how much one shared indicator is worth:
independence of the source and the type of indicator.

| Indicator | Independent source | Same source, different event type | Same source, same event type |
|---|---|---|---|
| Hash (SHA-256 / SHA-1 / MD5) | high | medium | not a link |
| IP address, domain, file path | medium | low | not a link |

Basis:
- Only information *"confirmed by other independent sources"* reaches the top
  credibility level of the Admiralty / NATO scale (US Army FM 2-22.3, also used by
  STIX 2.1 and MISP).
- Logs can be altered (NIST SP 800-86 §2.5), so links that all come from one
  source share the same weakness.
- An exact hash identifies one file. An IP address may be reassigned (DHCP) or
  shared by many hosts (NAT, proxies) (NIST SP 800-86 §6.4.4); domains and
  common paths are shared too.
- Repeats from one detection do not add weight; distinct sources do
  (Splunk risk-based alerting counts distinct sources).
- The NCA *Cybersecurity Event Logs and Monitoring Management Standard* requires
  correlation, documented alert thresholds, noise tuning and log integrity, but
  publishes no confidence scale; the table above applies the sources listed here.

Every finding stores its `rationale` text, e.g.
*"5 failed logons from 10.66.0.9 between 10:02:00 and 10:02:04 UTC (accounts: LAB\\bob ×5),
then a successful logon for LAB\\bob at 10:06:00 UTC, all within 10 minutes."*

Rules run in this order: single-source rules and R1–R3, then R4 (needs their
findings), then R5 (needs all suspicious findings). Re-running `atad correlate`
deletes the earlier rule findings and stores new ones; finding numbers keep
increasing, so an old id never points at a different finding.

The timeline is rebuilt each run: every evidence record with an event time,
plus one marker per finding at the time of its earliest evidence. Times are UTC.

Thresholds and disabled rules can be set in a YAML file (`--config`).
The test suite includes a labelled scenario with decoys for every rule and
checks precision and recall on it.

---

## 7.1 Reports and exports (M7)

| Output | Where | For | Notes |
|---|---|---|---|
| HTML report | `reports/CASE-x_report_<UTC>.html` | people | One self-contained file (no internet needed), light/dark, prints cleanly. Every finding links to its evidence |
| JSON report | `reports/CASE-x_report_<UTC>.json` | tools | Same data as the HTML (`format: atad-report`, `version: 1`), all evidence included |
| Timeline CSV / JSONL | `exports/CASE-x_timeline_<UTC>.csv/.jsonl` | Timeline Explorer, Timesketch, Elastic | CSV cells that start with `= + - @` get a leading `'` so spreadsheets do not run them as formulas |
| Case zip | `exports/CASE-x_case_<UTC>.zip` | handing a case to another analyst | Database snapshot (SQLite backup API), raw files, logs, reports and `SHA256SUMS.txt` |

Rules every report follows:
- Each output is a new read-only file; reports are recorded in the `reports` table with their SHA-256.
- Every raw file is hashed again while the report is built. A changed or missing file is shown at the top
  of the report and the command exits with code 4.
- Coverage lists every check, including those that failed, were unavailable or were skipped by choice,
  because "no finding" from a check that did not run means nothing.
- Simulated data is marked on the cover and on each simulated record.
- All collected text is HTML-escaped (Jinja2 autoescape).

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
atad ioc   load --path iocs.txt --case ...  |  list  |  check
atad correlate --case ... [--config thresholds.yaml]
atad findings  --case ... [--show FND-xxxx] [--min-severity ...]
atad timeline  --case ... [--host ...] [--findings-only]
atad report    --case ... [--format html|json|all]
atad export    timeline --case ... [--format csv|jsonl|all]
atad export    case --case ...
atad triage [--profile soc|dfir|full] [--only|--skip host,logs,files,net]
            [--path ...] [--target ...] [--iocs ...] [--hours N] [--case ...]
atad demo                                          SIMULATED demo case + precision/recall
```

Exit codes: `0` success, `1` error, `2` invalid input, `3` partial execution,
`4` report written but raw evidence changed or missing (integrity check failed).

---

### 9.4 Triage profiles (M8)

`atad triage` runs the modules of a profile on **this** machine, then correlates,
writes the HTML/JSON report and, for `dfir` and `full`, exports the timeline and
the case zip.

| Step | `soc` | `dfir` | `full` |
|---|---|---|---|
| host | all checks | all checks | all checks |
| logs (live) | last 24 h | last 7 days | last 7 days |
| files (with `--path`) | hash, info, YARA | hash, info, YARA | hash, info, YARA |
| net | interfaces; ping + DNS with `--target` | interfaces; DNS with `--target` | all checks, Nmap `quick`, with `--target` |
| IOC list (with `--iocs`) | loaded first | loaded first | loaded first |
| correlate + report | yes | yes | yes |
| timeline export + case zip | no | yes | yes |

Why: SOC triage must be quick and quiet, so it never scans. DFIR needs a wider log
window and a preserved copy to hand over. Only `full` sends an active scan, and only
to an authorized `--target`. Every input is validated before a case is created.

Step status: `done`; `limited` (a check is not available here, e.g. another OS);
`partial` (a check failed or timed out — exit code 3); `failed`; `skipped`.

### 9.5 Demo dataset and metrics (M8)

`atad demo` builds a **simulated** case (`src/atad/demo/data/scenario.json`): RDP
password guessing, encoded PowerShell, a disguised dropper that calls a C2 address
and adds a Run key, plus seven benign look-alikes (decoys). The data goes through the
real parsers — event XML through the log mapper, the dropper and decoy files through
the files module (hash, type, YARA), the host snapshot through the host converters,
the IOC list through the IOC loader. Only the collection step is replaced.

The scenario lists the findings that must appear. `atad demo` compares them with the
produced findings and reports precision (findings that were right) and recall
(expected findings that were found) per rule, and saves them as JSON. A finding whose
tool is missing (e.g. YARA) is reported as *not testable*, not as a miss.

Limits: the scenario was written by the same author as the rules, so 100% on it shows
the rules do what they were designed to do — not how they perform on real incidents.

---

## 10. Dependencies

| Mandatory (pip) | Optional (pip extra) | Optional (external, detected) |
|---|---|---|
| typer, pydantic, pyyaml, jinja2, psutil, evtx (Rust parser) | yara-python (`atad[yara]`), python-evtx (`atad[slow-evtx]`, fallback) | nmap, sysmon |

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
| M7 Reports | JSON + HTML report; timeline export as CSV / JSONL for Timeline Explorer, Timesketch and Elastic | Report built from demo case; every finding links to evidence; exports open in Timeline Explorer |
| M8 Triage & Demo | Profiles, `atad triage`, demo dataset, metrics | Full demo scenario runs end to end |
| M9 Linux | Linux adapters from §3.1 (ip, dig, journalctl, auth.log, auditd, persistence locations) | Same modules and commands work on Linux; Linux fixtures parse; `atad doctor` shows Linux tools instead of "n/a" |
| M10 Detection rules | Sigma rule support for log evidence (the standard used by Hayabusa and Chainsaw) | Public Sigma rules load and match labelled sample logs |

---

## 12. Lessons from established tools

How tools used in real SOC / DFIR work are built, and what atad takes from them:

| Practice | Seen in | atad |
|---|---|---|
| One executable, no install on the endpoint | Hayabusa, Chainsaw, Velociraptor | `atad.exe` built with PyInstaller (`packaging/build.py`) |
| Releases with published hashes | Hayabusa (signed releases) | `SHA256SUMS.txt` with every release; code signing not yet |
| Rules shipped next to the binary, updatable | Chainsaw, Hayabusa | `rules/` folder beside `atad.exe` |
| Fast EVTX parsing | Chainsaw (Rust EVTX parser) | Same Rust parser through the `evtx` package (~800× faster than python-evtx on the sample) |
| Works without extra infrastructure (no SIEM/ELK) | Chainsaw | Everything runs locally, offline; SQLite per case |
| Collection packed with a collection log | Velociraptor offline collector | Case folder with `logs/execution.jsonl`; `atad export case` packs it into one zip with SHA256SUMS.txt |
| Timeline export for analyst tools | Hayabusa (CSV/JSON/JSONL) | `atad export timeline`: CSV and JSONL with the Timesketch fields (`message`, `datetime`, `timestamp_desc`), `@timestamp` for Elastic |
| Sigma detection rules | Hayabusa, Chainsaw | Planned in M10 |
| Automated tests and builds | All maintained projects | GitHub Actions: tests on Windows + Linux, release build on tag |
