<!-- Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz) -->
<!-- SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0 -->

# ATAD risk register

**Document** ATAD-RISK-001 · **Version** 1.0 · **Applies to** ATAD 0.1.0 · **Owner** ATAD Team

A tool used in an investigation can be wrong in quiet ways: it can blame the
wrong machine, miss a step that failed, or present a guess as a fact. This
register lists the risks that matter most for ATAD, what ATAD does about each
one, and how that control is checked. It is reviewed with every release.

> [!NOTE]
> These are risks **to the quality and safety of an investigation that uses ATAD**,
> and to the project itself. They are not open defects. Known limits that remain
> after the controls are listed in [Residual risks](#residual-risks).

---

## How risks are rated

Likelihood (L) and impact (I) are each rated on three levels, in the style of
NIST SP 800-30 (simplified). The rating is the risk **before** ATAD's controls.

|                     | **Impact: low** | **Impact: medium** | **Impact: high** |
|---------------------|:---:|:---:|:---:|
| **Likely**          | 🟧 Medium | 🟥 High | 🟥 High |
| **Possible**        | 🟨 Low | 🟧 Medium | 🟥 High |
| **Unlikely**        | 🟨 Low | 🟨 Low | 🟧 Medium |

**Impact** describes what happens to the investigation: *high* = a wrong
conclusion or harm to a system, *medium* = a misleading or incomplete result
that a careful analyst could notice, *low* = extra work or a confusing output.

## Summary

| Area | Risks | Rated high before controls |
|---|:---:|:---:|
| [A. Evidence integrity](#a-evidence-integrity) | 4 | 3 |
| [B. Analysis quality](#b-analysis-quality) | 6 | 3 |
| [C. Safe operation](#c-safe-operation) | 4 | 3 |
| [D. Reporting and handling](#d-reporting-and-handling) | 2 | 1 |
| [E. Project and supply chain](#e-project-and-supply-chain) | 2 | 0 |
| **Total** | **18** | **10** |

---

## A. Evidence integrity

| ID | Risk | Before controls | Control in ATAD |
|---|---|---|---|
| **A1** | Evidence is attributed to the wrong machine (remote target labelled with data collected locally) | 🟥 High<br><sub>L: Possible · I: High</sub> | Three explicit collection modes: `local`, `import`, `network`. Every record stores its mode and host. Imported logs require `--source-host`; imported files take it when given<br><sub>Checked by: `test_cases.py`, `test_files_cli.py`</sub> |
| **A2** | A raw file changes after collection and the report no longer matches it | 🟧 Medium<br><sub>L: Unlikely · I: High</sub> | Every raw output is stored once, read-only, with its SHA-256. `atad report` hashes every file again, flags any change at the top of the report and exits with code 4<br><sub>Checked by: `test_reports.py`, `test_report_cli.py`</sub> |
| **A3** | Times from different sources or zones are compared wrongly, creating false links or missing real ones | 🟥 High<br><sub>L: Likely · I: High</sub> | All times stored as UTC. Linux syslog lines without a year or zone take them from the file date and `--timezone`, and each record keeps a `time_basis` note saying so<br><sub>Checked by: `test_linux_logs.py`</sub> |
| **A4** | One event is counted twice when two logs record it (auth.log and the journal) | 🟥 High<br><sub>L: Likely · I: Medium</sub> | R1 counts a logon once per host, second, IP, user, outcome and port, across log channels<br><sub>Checked by: `test_correlation.py`</sub> |

## B. Analysis quality

| ID | Risk | Before controls | Control in ATAD |
|---|---|---|---|
| **B1** | A finding cannot be explained, so it cannot be checked or defended | 🟥 High<br><sub>L: Possible · I: High</sub> | Every rule is documented ([architecture §7](architecture.md#7-correlation-rule-catalogue-mvp)). Each finding stores a plain-language reason and the exact evidence it rests on<br><sub>Checked by: `test_correlation.py`, `test_reports.py`</sub> |
| **B2** | False positives bury real activity | 🟥 High<br><sub>L: Likely · I: Medium</sub> | Narrow rules (S2 flags only disguised programs; S3 judges shortcuts by their real target). Confidence is separate from severity. Labelled demo with decoys measures precision and recall<br><sub>Checked by: `test_files.py` (real false positives from a laptop), `test_demo_triage.py`</sub> |
| **B3** | One indicator seen twice in the same log is treated as strong confirmation | 🟧 Medium<br><sub>L: Possible · I: Medium</sub> | R4 confidence depends on source independence and indicator type (Admiralty scale, NIST SP 800-86 §2.5, §6.4.4). Repeats of the same event type are not links<br><sub>Checked by: `test_correlation.py`</sub> |
| **B4** | "Tool not available" or "no admin rights" is read as "nothing found" | 🟥 High<br><sub>L: Likely · I: High</sub> | Each run has a status: success, failed, timeout, skipped, unavailable. Triage shows done / limited / partial / failed / skipped. Missing admin rights are detected and recorded with every run. The report has a coverage section<br><sub>Checked by: `test_execution.py`</sub> |
| **B5** | Process links are wrong because Windows reuses PIDs | 🟧 Medium<br><sub>L: Possible · I: Medium</sub> | Sysmon `ProcessGuid` is preferred; the PID together with the program path is the fallback only<br><sub>Checked by: `test_correlation.py`</sub> |
| **B6** | Results cannot be reproduced because tool versions are unknown | 🟧 Medium<br><sub>L: Possible · I: Medium</sub> | `atad doctor` before work; the tool version is stored with every execution and listed in the report's coverage section<br><sub>Checked by: `test_doctor.py`, `test_adapters.py`</sub> |

## C. Safe operation

| ID | Risk | Before controls | Control in ATAD |
|---|---|---|---|
| **C1** | Input passed to a tool runs as a command (command injection) | 🟥 High<br><sub>L: Possible · I: High</sub> | Tools run with argument lists, never `shell=True`. Targets, ports, case IDs and paths are validated before anything runs<br><sub>Checked by: `test_execution.py`, `test_validation.py`, `test_host_net_cli.py`</sub> |
| **C2** | A network scan reaches a system the analyst is not authorized to test | 🟥 High<br><sub>L: Possible · I: High</sub> | Every case has an authorized scope. Public addresses need `--allow-public`; large ranges are refused. Only the `full` triage profile scans, and only an authorized `--target`<br><sub>Checked by: `test_validation.py`, `test_host_net_cli.py`</sub> |
| **C3** | The tool changes the system under investigation | 🟧 Medium<br><sub>L: Unlikely · I: High</sub> | Read-only by design: ATAD never deletes, quarantines, blocks or executes what it investigates. Its own case folders are excluded from scans<br><sub>Checked by: `test_files.py`</sub> |
| **C4** | A hostile or broken rule file stops the analysis or abuses the parser | 🟥 High<br><sub>L: Possible · I: High</sub> | YAML is read with the safe loader. A broken Sigma rule is reported and skipped while the others run; YARA rules that fail to compile are reported and the other checks still run<br><sub>Checked by: `test_sigma.py`</sub> |

## D. Reporting and handling

| ID | Risk | Before controls | Control in ATAD |
|---|---|---|---|
| **D1** | Collected text injects code into the HTML report, or formulas into a spreadsheet | 🟥 High<br><sub>L: Possible · I: High</sub> | HTML templates escape everything. CSV cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return are neutralised<br><sub>Checked by: `test_reports.py`</sub> |
| **D2** | A report is shared more widely than intended, or simulated data is taken as real | 🟧 Medium<br><sub>L: Possible · I: Medium</sub> | TLP 2.0 label on every report (default `amber`). Simulated cases carry a flag on every record and a banner in the report<br><sub>Checked by: `test_reports.py`, `test_demo_triage.py`</sub> |

## E. Project and supply chain

| ID | Risk | Before controls | Control in ATAD |
|---|---|---|---|
| **E1** | A modified copy is published under the ATAD name and harms its users | 🟧 Medium<br><sub>L: Possible · I: Medium</sub> | Modified versions must use another name ([TRADEMARKS.md](../TRADEMARKS.md)). Releases publish SHA-256 sums<br><sub>Checked by: Release workflow</sub> |
| **E2** | A third-party licence condition is missed | 🟨 Low<br><sub>L: Unlikely · I: Medium</sub> | [NOTICE](../NOTICE) and `THIRD_PARTY_LICENSES/` in every release. Sigma findings name the rule's author, as the Detection Rule License requires<br><sub>Checked by: `test_sigma.py`</sub> |

---

## Residual risks

These remain after the controls above. Analysts should keep them in mind.

| Limit | What it means | Mitigation for the analyst |
|---|---|---|
| S3 cannot tell some legitimate per-user apps from malware by location alone | Apps such as Spotify install in AppData and may be flagged | S3 findings have low confidence; confirm with R4 links or the file's signature |
| Sigma aggregations and correlation rules are not supported | Rules with `count()` are skipped, with the reason shown | Use the R1 rule for brute force, or a SIEM for aggregation rules |
| Live collection sees only what the logs and the OS keep | Cleared or rotated logs, and activity in memory only, are not visible | Collect early; add memory forensics tools for advanced cases |
| Findings are leads, not verdicts | A rule match does not prove compromise | Confirm every finding before acting, as the report states |

## Review history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-11-08 | First register: 18 risks across five areas |
