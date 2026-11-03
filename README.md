# atad (عَتاد)

**Advanced Toolkit for Attack & Defense** — one CLI that runs established
SOC/DFIR tools, keeps their original outputs as evidence, normalizes the
results, correlates them across sources and produces an investigation report.

```
Collect → Normalize → Correlate → Investigate → Report
```

> Status: early development (milestone M4 — log investigation).
> MVP platform: Windows. Read-only by design: atad never deletes, quarantines,
> blocks or executes anything it investigates.

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
```

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
