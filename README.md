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

## Usage (current milestone)

```bash
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
```

Without `--case`, `atad net` creates a case and authorizes its `--target`.
With `--case`, the target must already be in that case's scope
(`atad scope add`). Public addresses need `--allow-public`.

YARA rules are read from `--rules`, `$ATAD_RULES` or `./rules`.
`rules/demo/` holds demo rules that match **simulated** markers only.
Install YARA support with `pip install -e ".[yara]"`.

Imported `.evtx` files are copied into the case (read-only, hashed) and atad
reads only its copy. Large logs are slow to parse in pure Python
(about 300 records per second); live collection filters to the supported
event IDs and the `--hours` window first.

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

