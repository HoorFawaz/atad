# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Build the demo case from the bundled SIMULATED scenario.

The demo goes through the same code as real evidence: event XML is parsed by
the log parser and mapper, the dropper and decoy files are written to a
temporary folder and examined by the real files module (hashes, type, YARA),
the host snapshot goes through the host converters, and the IOC list through
the IOC loader. Only the collection step itself is replaced by the dataset.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from atad.cases.manager import CaseManager, OpenCase
from atad.core.execution import execute_collector
from atad.evidence.models import (
    CollectionMode,
    Evidence,
    ExecutionStatus,
    Profile,
    SourceModule,
)
from atad.modules.common import CheckOutcome, run_collector_check
from atad.modules.files.runner import CHECKS as FILE_CHECKS
from atad.modules.files.runner import run_files
from atad.modules.host import collector as hc
from atad.modules.ioc.loader import load_ioc_file
from atad.modules.logs.evtx_reader import parse_event_xml
from atad.modules.logs.mapping import event_to_evidence, is_supported
from atad.modules.logs.runner import SYSMON, _ctx

SECURITY_CHANNEL = "Security"
PROVIDERS = {"Security": "Microsoft-Windows-Security-Auditing", "Sysmon": "Microsoft-Windows-Sysmon"}
DEMO_RULE = """// SIMULATED demo rule (same as rules/demo/atad_demo.yar). Matches a harmless marker only.
rule ATAD_Demo_Simulated_Dropper
{
    meta:
        description = "Matches the simulated dropper marker used in the ATAD demo"
        simulated = "true"
        severity = "high"
    strings:
        $marker = "ATAD-DEMO-SIMULATED-DROPPER" ascii wide
    condition:
        $marker
}
"""


def load_scenario() -> dict[str, Any]:
    text = (resources.files("atad.demo") / "data" / "scenario.json").read_text(encoding="utf-8")
    return json.loads(text)


def _file_bytes(spec: dict) -> bytes:
    return spec["content"].encode("utf-8")


def dropper_sha256(scenario: dict) -> str:
    spec = next(f for f in scenario["files"] if f["name"] == "invoice.pdf.exe")
    return hashlib.sha256(_file_bytes(spec)).hexdigest()


def _fill(value: Any, sha: str) -> Any:
    if isinstance(value, str):
        return value.replace("{dropper_sha256}", sha.upper() if value.startswith("SHA256=") else sha)
    if isinstance(value, dict):
        return {k: _fill(v, sha) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, sha) for v in value]
    return value


def event_xml(ev: dict, record_id: int, computer: str) -> str:
    channel = SYSMON if ev["ch"] == "Sysmon" else SECURITY_CHANNEL
    fields = "".join(f'<Data Name="{escape(k)}">{escape(str(v))}</Data>' for k, v in ev["d"].items())
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{PROVIDERS[ev["ch"]]}"></Provider><EventID>{ev["id"]}</EventID>'
        f'<TimeCreated SystemTime="{ev["t"]}"></TimeCreated><EventRecordID>{record_id}</EventRecordID>'
        f'<Channel>{channel}</Channel><Computer>{escape(computer)}</Computer></System>'
        f'<EventData>{fields}</EventData></Event>'
    )


@dataclass
class DemoBuild:
    case: OpenCase
    scenario: dict
    yara_available: bool
    steps: list[tuple[str, int]] = field(default_factory=list)   # (step, evidence count)


def _store_events(oc: OpenCase, scenario: dict, sha: str) -> int:
    host = scenario["host"]
    events = _fill(scenario["events"], sha)
    xml_lines = [event_xml(ev, 1000 + i, f"{host}.lab.test") for i, ev in enumerate(events)]
    rec = execute_collector(
        oc, module=SourceModule.LOG, tool="atad-demo-events", tool_version=None,
        collection_mode=CollectionMode.IMPORT, target="demo dataset (simulated event log)",
        description=["demo-events"],
        collect=lambda: ("\n".join(xml_lines) + "\n").encode("utf-8"),
    )
    ctx = _ctx(oc, rec.execution, host, CollectionMode.IMPORT, True, None, tool="atad-demo-events")
    batch: list[Evidence] = []
    for line in xml_lines:
        event = parse_event_xml(line)
        if event and is_supported(event):
            ev = event_to_evidence(event, ctx)
            if ev is not None:
                batch.append(ev)
    batch.sort(key=lambda e: (e.event_time is None, e.event_time))
    return len(oc.repo.add_evidence_many(batch))


def _store_host(oc: OpenCase, scenario: dict, sha: str) -> int:
    snap = _fill(scenario["host_snapshot"], sha)
    host = scenario["host"]
    procs = []
    for p in snap["processes"]:
        p = {"sha256": None, **p}
        p["suspicious_reasons"] = hc.process_flags(p.get("exe"), p.get("cmdline"), True)
        procs.append(p)
    startup = []
    for s in snap["startup"]:
        exe = (s.get("executable") or "").lower()
        s = {**s, "suspicious_reasons": (["starts from a user-writable folder"]
                                         if any(d in exe for d in hc._USER_WRITABLE) else [])}
        startup.append(s)
    captures = {
        "processes": ({"check": "processes", "count": len(procs), "records": procs},
                      hc.processes_to_evidence),
        "connections": ({"check": "connections", "count": len(snap["connections"]),
                         "records": snap["connections"]}, hc.connections_to_evidence),
        "startup": ({"check": "startup", "count": len(startup), "errors": [], "records": startup},
                    hc.startup_to_evidence),
    }
    n = 0
    for check, (cap, convert) in captures.items():
        out: CheckOutcome = run_collector_check(
            oc, module=SourceModule.HOST, check=check, tool="atad-demo-host", tool_version=None,
            mode=CollectionMode.IMPORT, host=host, host_declared=True,
            target="demo dataset (simulated host snapshot)",
            collect=lambda c=cap: c,
            # Label the records with their real source: the dataset, not psutil.
            to_evidence=lambda c, ctx, conv=convert: [
                e.model_copy(update={"source_tool": "atad-demo-host"}) for e in conv(c, ctx)])
        n += len(out.evidence)
    return n


def build_demo(manager: CaseManager) -> DemoBuild:
    scenario = load_scenario()
    sha = dropper_sha256(scenario)
    oc = manager.create_case(scenario["name"], Profile.DFIR, description=scenario["description"],
                             simulated=True)
    build = DemoBuild(case=oc, scenario=scenario, yara_available=False)

    with tempfile.TemporaryDirectory(prefix="atad-demo-") as tmp:
        tmp_path = Path(tmp)
        ioc_file = tmp_path / "demo-iocs.csv"
        ioc_file.write_text(scenario["iocs_csv"], encoding="utf-8")
        load = load_ioc_file(oc, ioc_file, name="demo-iocs.csv (simulated)")
        build.steps.append(("indicators", len(load.iocs)))

        build.steps.append(("event log", _store_events(oc, scenario, sha)))

        suspect = tmp_path / "collected-from-LAB-WS-07"
        suspect.mkdir()
        for spec in scenario["files"]:
            p = suspect / spec["name"]
            p.write_bytes(_file_bytes(spec))
            ts = datetime.fromisoformat(spec["modified"]).timestamp()
            os.utime(p, (ts, ts))
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "atad_demo.yar").write_text(DEMO_RULE, encoding="utf-8")
        files = run_files(oc, suspect, FILE_CHECKS, source_host=scenario["host"], rules=rules)
        scan = files.outcome("scan")
        build.yara_available = bool(scan and scan.execution.status is ExecutionStatus.SUCCESS)
        build.steps.append(("files", len(files.evidence)))

        build.steps.append(("host snapshot", _store_host(oc, scenario, sha)))
    return build
