# atad (عَتاد)

**Advanced Toolkit for Attack & Defense** — one CLI that runs established
SOC/DFIR tools, keeps their original outputs as evidence, normalizes the
results, correlates them across sources and produces an investigation report.

```
Collect → Normalize → Correlate → Investigate → Report
```

> Status: early development (milestone M3 — file investigation).
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
```

YARA rules are read from `--rules`, `$ATAD_RULES` or `./rules`.
`rules/demo/` holds demo rules that match **simulated** markers only.
Install YARA support with `pip install -e ".[yara]"`.

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
