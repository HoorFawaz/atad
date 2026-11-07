# ATAD (عَتاد)

**Advanced Toolkit for Attack & Defense** — one CLI that runs established
security tools, keeps their original outputs as evidence, normalizes the
results, correlates them across sources and produces an investigation report.

```
Collect → Normalize → Correlate → Investigate → Report
```

> Status: early development (milestone M5 — host & network, single-file build).
> Current modules are defensive (SOC / DFIR). Offensive (red team) modules are planned.
> MVP platform: Windows. Read-only by design: atad never deletes, quarantines,
> blocks or executes anything it investigates.

## Install

**Analysts:** download `atad-<version>-windows-x86_64.zip` from Releases, check it
against `SHA256SUMS.txt`, unzip, and run `atad.exe` — no Python needed.
Keep the `rules` folder next to `atad.exe`.

```powershell
Get-FileHash .\atad-0.1.0-windows-x86_64.zip -Algorithm SHA256
.\atad\atad.exe doctor
```

**Build the executable yourself** (on Windows): `pip install -e ".[yara]" pyinstaller`
then `python packaging/build.py` → `dist\atad.exe`.

## Install (development)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e ".[dev]"
```

## Usage

```bash
atad demo                       # SIMULATED demo case: findings, report, precision/recall
atad triage --profile soc       # first look at THIS machine: all modules, correlate, report
atad triage --profile dfir --path .\evidence --iocs .\iocs.txt
atad triage --profile full --target 192.168.1.15 --skip files

atad doctor                     # which tools are installed, admin rights
atad case new --name "Suspicious workstation" --profile soc
atad case list
atad case show CASE-001
atad scope add --case CASE-001 --target 192.168.1.15

# File investigation (read-only)
atad files --path .\evidence                      # hash + info + YARA scan
atad files --path .\evidence --only hash,scan     # chosen checks
atad files --path .\evidence --skip scan          # all except YARA
atad files hash --path .\evidence\sample.exe       # one check
atad files --path E:\copied --source-host WS-07   # files copied from another machine

# Windows event logs (Security 4624/4625/4688/4720, Sysmon 1/3/11)
atad log                                           # live, on the suspect machine (admin)
atad log --only security --hours 48
atad log import --path E:\logs --source-host WS-07  # .evtx copied from another machine
atad log search --case CASE-001 --keyword failed_login

# This machine (run atad on the suspect machine, as admin)
atad host                                          # info, processes, connections, users, startup
atad host --only processes,connections
atad host startup

# Network (authorized targets only)
atad net --target 192.168.1.15                     # interfaces + ping + Nmap + DNS
atad net --target 192.168.1.0/24 --only scan --profile quick
atad net scan --target 192.168.1.15 --ports 22,80,443,3389
atad net interfaces

# Indicators and correlation
atad ioc load --case CASE-001 --path .\iocs.txt     # .txt (one per line) or .csv
atad ioc list --case CASE-001
atad ioc check --case CASE-001                     # which indicators appear (read-only)
atad correlate --case CASE-001                     # link evidence into findings + timeline
atad correlate --case CASE-001 --config .\correlation.yaml
atad findings --case CASE-001 --min-severity high
atad findings --case CASE-001 --show FND-0004      # why, and the evidence behind it
atad timeline --case CASE-001 --findings-only

# Reports and exports
atad report --case CASE-001                        # HTML + JSON into the case's reports folder
atad report --case CASE-001 --format html
atad export timeline --case CASE-001               # CSV + JSONL (Timesketch, Timeline Explorer, Elastic)
atad export case --case CASE-001                   # whole case as one zip with SHA256SUMS.txt
```

Without `--case`, `atad net` creates a case and authorizes its `--target`.
With `--case`, the target must already be in that case's scope
(`atad scope add`). Public addresses need `--allow-public`.

YARA rules are read from `--rules`, `$ATAD_RULES` or `./rules`.
`rules/demo/` holds demo rules that match **simulated** markers only.
Install YARA support with `pip install -e ".[yara]"`.

Imported `.evtx` files are copied into the case (read-only, hashed) and atad
reads only its copy. Live collection filters to the supported event IDs and
the `--hours` window first.

IOC lists are copied into the case the same way. Defanged indicators
(`hxxp://`, `evil[.]com`) are accepted. A CSV needs a `value` column and may add
`type`, `confidence` (low/medium/high) and `description`.

`atad correlate` can be run as often as needed: it replaces its earlier findings
and rebuilds the timeline. Every finding says in plain words why the evidence was
linked. Thresholds can be changed with a YAML file:

```yaml
r1_min_failures: 5      # failed logons before a success
r1_window_minutes: 10
r5_min_findings: 3      # suspicious findings on one host
r5_window_minutes: 15
disabled_rules: [S2]
```

`atad report` hashes every raw file again. If one changed or is missing, the
report says so at the top and the command exits with code 4.

Cases are stored in `./cases` (override with `--home` or the `ATAD_HOME`
environment variable).

## Collection modes

| Mode | Meaning |
|---|---|
| `local` | atad runs on the suspect machine and collects from it |
| `import` | evidence copied from the suspect machine is imported with `--path` |
| `network` | network checks against an authorized `--target` |

## Documentation

- [Architecture & design](docs/architecture.md)

## Tests

```bash
pytest
```

## License

Copyright (C) 2026 Hoor Fawaz

ATAD is **source-available** under the ATAD Source-Available License 1.0
([English](LICENSE) · [العربية — النص الرسمي](LICENSE.ar)). It is not an
OSI-approved open source license.

| | |
|---|---|
| Personal and internal use, including by companies | Free |
| Using ATAD as a tool in paid services (SOC, incident response, consulting) | Free |
| Free redistribution, with source, notices and a new name for modified versions | Free |
| Selling ATAD, bundling it in a paid or closed product, or offering it as a paid service | Written permission required |

Reports and evidence produced with ATAD belong to their user.
For commercial licensing: hoorfawaz.it@gmail.com

Third-party components and their licenses are listed in [NOTICE](NOTICE).
Use of the ATAD name and logo is covered by [TRADEMARKS.md](TRADEMARKS.md).

