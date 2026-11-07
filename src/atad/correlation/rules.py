# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Correlation rules.

Each rule reads the case's evidence and returns findings. A rule never
invents facts: every finding lists the evidence it is built on and a
rationale that says, in plain words, why that evidence was linked.

| Rule | What it finds                                         | Category    |
|------|-------------------------------------------------------|-------------|
| IOC  | Evidence that contains a known indicator               | suspicious  |
| YARA | A file that matched a YARA rule                        | suspicious  |
| S1   | PowerShell started with an encoded command             | suspicious  |
| S2   | A file whose real type does not match its name         | suspicious  |
| S3   | Auto-start entry that runs from a user-writable folder | suspicious  |
| R1   | Many failed logons from one source (with or without a success) | suspicious |
| R2   | A process that connected to a known indicator          | suspicious  |
| R3   | A file that matched YARA was also run as a process     | suspicious  |
| R4   | A finding's key indicator seen in another source or event type | correlated |
| R5   | Several suspicious findings close in time on one host  | hypothesis  |
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import PureWindowsPath
from typing import Iterable

from atad.correlation.config import CorrelationConfig
from atad.evidence.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    Ioc,
    Observable,
    Severity,
)
from atad.modules.host.collector import ENCODED_POWERSHELL
from atad.modules.ioc.parser import url_host

BASE_RULES = ("IOC", "YARA", "S1", "S2", "S3", "R1", "R2", "R3")
ALL_RULES = BASE_RULES + ("R4", "R5")

_SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_CONF_TO_SEV = {Confidence.LOW: Severity.LOW, Confidence.MEDIUM: Severity.MEDIUM,
                Confidence.HIGH: Severity.HIGH}
_CONF_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
PIVOT_TYPES = ("ip", "domain", "sha256", "sha1", "md5", "path")


def max_severity(items: Iterable[Severity]) -> Severity:
    return max(items, key=_SEV_ORDER.index, default=Severity.INFO)


def short(value: str, width: int = 40) -> str:
    """Long values (hashes, URLs) are shortened in titles; rationales keep them whole."""
    return value if len(value) <= width else value[:width - 1] + "…"


def fmt_iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat()


def fmt_time(t: datetime | None) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S UTC") if t else "unknown time"


def host_key(host: str) -> str:
    """Compare hosts loosely: case-insensitive, short name for hostnames."""
    h = host.strip().lower()
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        return h.split(".")[0]


def name_of(path: str | None) -> str:
    return PureWindowsPath(path).name if path else "?"


# --------------------------------------------------------------------------- #
# Shared view of the case
# --------------------------------------------------------------------------- #


@dataclass
class CaseView:
    case_id: str
    evidence: list[Evidence]
    iocs: list[Ioc]
    by_id: dict[str, Evidence] = field(default_factory=dict)
    by_obs: dict[tuple[str, str], list[str]] = field(default_factory=lambda: defaultdict(list))
    own_ips: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        for e in self.evidence:
            self.by_id[e.id] = e
            for o in e.observables:
                self.by_obs[(o.type.value, o.value)].append(e.id)
            if e.kind is EvidenceKind.INTERFACE:
                self.own_ips.update(o.value for o in e.observables if o.type.value == "ip")

    def kind(self, *kinds: EvidenceKind) -> list[Evidence]:
        return [e for e in self.evidence if e.kind in kinds]

    def ioc_index(self) -> "IocIndex":
        return IocIndex(self.iocs)


class IocIndex:
    """Fast lookup: does an observable match a loaded indicator?"""

    def __init__(self, iocs: list[Ioc]) -> None:
        self.exact: dict[tuple[str, str], list[Ioc]] = defaultdict(list)
        self.nets: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Ioc]] = []
        for i in iocs:
            if i.type == "cidr":
                self.nets.append((ipaddress.ip_network(i.value, strict=False), i))
            elif i.type == "url":
                self.exact[("url", i.value)].append(i)
                host = url_host(i.value)
                if host:
                    self.exact[("domain", host)].append(i)
            else:
                self.exact[(i.type, i.value)].append(i)

    def match(self, obs: Observable) -> list[Ioc]:
        hits = list(self.exact.get((obs.type.value, obs.value), []))
        if obs.type.value == "ip" and self.nets:
            addr = ipaddress.ip_address(obs.value)
            hits += [i for net, i in self.nets if addr.version == net.version and addr in net]
        return hits


def _finding(view: CaseView, rule: str, title: str, category: FindingCategory,
             severity: Severity, confidence: Confidence, rationale: str,
             evidence_ids: Iterable[str], description: str = "") -> Finding:
    ids = list(dict.fromkeys(evidence_ids))
    return Finding(case_id=view.case_id, title=title, description=description,
                   category=category, severity=severity, confidence=confidence,
                   rule_id=rule, rationale=rationale, evidence_ids=ids)


@dataclass
class RuleResult:
    finding: Finding
    keys: set[Observable] = field(default_factory=set)   # observables worth pivoting on


# --------------------------------------------------------------------------- #
# IOC — indicator matches
# --------------------------------------------------------------------------- #


def rule_ioc(view: CaseView) -> list[RuleResult]:
    index = view.ioc_index()
    groups: dict[tuple[str, str], dict] = {}
    for e in view.evidence:
        if e.kind is EvidenceKind.INTERFACE:
            continue  # this machine's own addresses are not sightings
        for o in e.observables:
            for i in index.match(o):
                g = groups.setdefault((i.type, i.value), {"iocs": {}, "ev": [], "via": set()})
                g["iocs"][i.source] = i
                g["ev"].append(e.id)
                if (o.type.value, o.value) != (i.type, i.value):
                    g["via"].add(f"{o.type.value} {o.value}")
    out = []
    for (kind, value), g in sorted(groups.items()):
        iocs = list(g["iocs"].values())
        conf = max((i.confidence for i in iocs), key=_CONF_ORDER.index)
        ev = list(dict.fromkeys(g["ev"]))
        modules = sorted({view.by_id[x].source_module.value for x in ev})
        sources = ", ".join(sorted(g["iocs"]))
        via = f" (matched through {', '.join(sorted(g['via']))})" if g["via"] else ""
        desc = "; ".join(sorted({i.description for i in iocs if i.description}))
        rationale = (f"Indicator {kind} {value} from IOC list(s) {sources} (confidence "
                     f"{conf.value}) appears in {len(ev)} evidence record(s) from "
                     f"{', '.join(modules)}{via}. A match shows the indicator was seen; "
                     f"it does not by itself prove compromise.")
        out.append(RuleResult(
            _finding(view, "IOC", f"Known indicator seen: {short(value)}", FindingCategory.SUSPICIOUS,
                     _CONF_TO_SEV[conf], conf, rationale, ev, desc),
            keys={Observable(type=kind, value=value)} if kind not in ("cidr", "url") else set(),
        ))
    return out


# --------------------------------------------------------------------------- #
# YARA / S1 / S2 — single-source suspicious evidence
# --------------------------------------------------------------------------- #


def _file_keys(e: Evidence) -> set[Observable]:
    return {o for o in e.observables if o.type.value in ("sha256", "sha1", "md5", "path")}


def rule_yara(view: CaseView) -> list[RuleResult]:
    out = []
    for e in view.kind(EvidenceKind.YARA_MATCH):
        meta_sev = str(e.data.get("meta", {}).get("severity", "")).lower()
        sev = Severity(meta_sev) if meta_sev in {s.value for s in Severity} else Severity.MEDIUM
        rule = e.data.get("rule", "?")
        rationale = (f"File {e.data.get('path')} (SHA-256 {e.data.get('sha256', '?')[:16]}…) on "
                     f"{e.host} matched YARA rule '{rule}'. The rule's own severity is used; "
                     f"YARA rules can produce false positives.")
        out.append(RuleResult(
            _finding(view, "YARA", f"YARA rule '{rule}' matched {name_of(e.data.get('path'))}",
                     FindingCategory.SUSPICIOUS, sev, Confidence.MEDIUM, rationale, [e.id]),
            keys=_file_keys(e)))
    return out


def _command_line(e: Evidence) -> str | None:
    return e.data.get("command_line") or e.data.get("cmdline")


def rule_encoded_powershell(view: CaseView) -> list[RuleResult]:
    groups: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    for e in view.kind(EvidenceKind.PROCESS):
        cmd = _command_line(e)
        if cmd and ENCODED_POWERSHELL.search(cmd + " "):
            groups[(host_key(e.host), " ".join(cmd.split()).lower())].append(e)
    out = []
    for (_, _), evs in sorted(groups.items()):
        first = min(evs, key=lambda x: (x.event_time is None, x.event_time))
        cmd = _command_line(first)
        rationale = (f"PowerShell was started with an encoded command on {first.host} at "
                     f"{fmt_time(first.event_time)}: \"{cmd[:160]}\". Attackers often hide "
                     f"commands this way; some admin tools do too. Seen in {len(evs)} record(s).")
        out.append(RuleResult(
            _finding(view, "S1", f"Encoded PowerShell command on {first.host}",
                     FindingCategory.SUSPICIOUS, Severity.MEDIUM, Confidence.MEDIUM, rationale,
                     [x.id for x in evs])))
    return out


def rule_disguised_file(view: CaseView) -> list[RuleResult]:
    out = []
    for e in view.kind(EvidenceKind.FILE):
        reasons = e.data.get("suspicious_reasons") or []
        if not reasons:
            continue
        rationale = (f"File {e.data.get('path')} on {e.host}: " + "; ".join(reasons) +
                     ". A file that hides its real type is a common way to trick users "
                     "into running it.")
        out.append(RuleResult(
            _finding(view, "S2", f"Disguised file: {e.data.get('name')}",
                     FindingCategory.SUSPICIOUS, Severity.MEDIUM, Confidence.MEDIUM, rationale,
                     [e.id]),
            keys=_file_keys(e)))
    return out


# --------------------------------------------------------------------------- #
# S3 — auto-start (persistence) from a user-writable folder
# --------------------------------------------------------------------------- #

_AUTOSTART = {
    "registry_run": ("Run key", "T1547.001 Registry Run Keys / Startup Folder"),
    "startup_folder": ("Startup folder entry", "T1547.001 Registry Run Keys / Startup Folder"),
    "service": ("Auto-start service", "T1543.003 Windows Service"),
}


def rule_suspicious_autostart(view: CaseView) -> list[RuleResult]:
    groups: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    for e in view.kind(EvidenceKind.PERSISTENCE):
        exe = e.data.get("executable")
        if exe and e.data.get("suspicious_reasons"):
            groups[(host_key(e.host), exe.lower())].append(e)
    out = []
    for _, evs in sorted(groups.items()):
        e = evs[0]
        label, technique = _AUTOSTART.get(e.data.get("type"), ("Auto-start entry", "T1547"))
        entries = "; ".join(f"{_AUTOSTART.get(x.data.get('type'), (label,))[0]} '{x.data.get('name')}'"
                            f" in {x.data.get('location')}" for x in evs)
        rationale = (f"{entries} on {e.host} starts {e.data.get('executable')} — "
                     + "; ".join(e.data["suspicious_reasons"]) + ". Programs that start "
                     f"automatically from a folder any user can write to are a common way for "
                     f"malware to survive a restart (MITRE ATT&CK {technique}). Some legitimate "
                     "per-user applications install there too, so confidence is low until "
                     "another finding points to the same program.")
        keys = {o for x in evs for o in x.observables if o.type.value in ("path", "sha256")}
        out.append(RuleResult(
            _finding(view, "S3", f"Auto-start from a user-writable folder: "
                                 f"{name_of(e.data.get('executable'))}",
                     FindingCategory.SUSPICIOUS, Severity.MEDIUM, Confidence.LOW, rationale,
                     [x.id for x in evs]),
            keys=keys))
    return out


# --------------------------------------------------------------------------- #
# R1 — repeated failed logons (password guessing), with or without success
# --------------------------------------------------------------------------- #


def _bursts(fails: list[Evidence], window: timedelta) -> list[list[Evidence]]:
    """Split failures into bursts: a gap longer than the window starts a new one."""
    out: list[list[Evidence]] = []
    for f in fails:
        if out and f.event_time - out[-1][-1].event_time <= window:
            out[-1].append(f)
        else:
            out.append([f])
    return out


def _dense_enough(burst: list[Evidence], window: timedelta, minimum: int) -> bool:
    """True when some stretch of `window` holds at least `minimum` failures."""
    j = 0
    for i in range(len(burst)):
        while burst[i].event_time - burst[j].event_time > window:
            j += 1
        if i - j + 1 >= minimum:
            return True
    return False


def rule_bruteforce(view: CaseView, cfg: CorrelationConfig) -> list[RuleResult]:
    window = timedelta(minutes=cfg.r1_window_minutes)
    by_src: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    for e in view.kind(EvidenceKind.LOGON):
        ip, t = e.data.get("source_ip"), e.event_time
        if ip and t and e.data.get("outcome") in ("failure", "success"):
            by_src[(host_key(e.host), ip)].append(e)
    out = []
    for (_, ip), evs in sorted(by_src.items()):
        evs.sort(key=lambda x: x.event_time)
        fails = [e for e in evs if e.data["outcome"] == "failure"]
        successes = [e for e in evs if e.data["outcome"] == "success"]
        for burst in _bursts(fails, window):
            if not _dense_enough(burst, window, cfg.r1_min_failures):
                continue
            start, end = burst[0].event_time, burst[-1].event_time
            targets = Counter(f.data.get("user") or "?" for f in burst)
            accounts = ", ".join(f"{u} ×{n}" for u, n in targets.most_common(3))
            if len(targets) > 3:
                accounts += f" and {len(targets) - 3} more"
            head = (f"{len(burst)} failed logons from {ip} on {burst[0].host} between "
                    f"{fmt_time(start)} and {fmt_time(end)} (accounts: {accounts})")
            # First success per account during the burst or within the window after it
            won: dict[str, Evidence] = {}
            for s in successes:
                if start < s.event_time <= end + window:
                    won.setdefault(s.data.get("user") or "?", s)
            if won:
                who = ", ".join(f"{u} at {fmt_time(s.event_time)}" for u, s in won.items())
                rationale = (f"{head}, then a successful logon for {who}. This pattern fits "
                             f"password guessing that succeeded; confirm with the account owner.")
                finding = _finding(view, "R1", f"Repeated failed logons then success from {ip}",
                                   FindingCategory.SUSPICIOUS, Severity.HIGH, Confidence.HIGH,
                                   rationale, [f.id for f in burst] + [s.id for s in won.values()])
            else:
                rationale = (f"{head}. No successful logon from {ip} followed within "
                             f"{cfg.r1_window_minutes} minutes. Someone tried to guess a password "
                             f"and has not succeeded in the collected logs; check whether the "
                             f"attempts continue or the account is locked.")
                finding = _finding(view, "R1", f"Repeated failed logons from {ip} (no success seen)",
                                   FindingCategory.SUSPICIOUS, Severity.MEDIUM, Confidence.HIGH,
                                   rationale, [f.id for f in burst])
            out.append(RuleResult(finding, keys={Observable(type="ip", value=ip)}))
    return out


# --------------------------------------------------------------------------- #
# R2 — process connected to an indicator
# --------------------------------------------------------------------------- #


def _obs(e: Evidence, kind: str) -> set[str]:
    return {o.value for o in e.observables if o.type.value == kind}


def _find_process(view: CaseView, conn: Evidence) -> tuple[list[Evidence], str]:
    procs = [p for p in view.kind(EvidenceKind.PROCESS) if host_key(p.host) == host_key(conn.host)]
    guids = _obs(conn, "process_guid")
    if guids:
        hit = [p for p in procs if _obs(p, "process_guid") & guids]
        if hit:
            return hit, "Sysmon ProcessGuid"
    pids, paths = _obs(conn, "pid"), _obs(conn, "path")
    if pids and paths:
        hit = [p for p in procs if _obs(p, "pid") & pids and _obs(p, "path") & paths]
        if hit:
            return hit, "same PID and program path"
    return [], ""


def rule_ioc_connection(view: CaseView) -> list[RuleResult]:
    index = view.ioc_index()
    groups: dict[tuple, dict] = {}
    for c in view.kind(EvidenceKind.NETWORK_CONNECTION):
        hits = [(o, i) for o in c.observables if o.type.value in ("ip", "domain")
                for i in index.match(o)]
        if not hits:
            continue
        procs, how = _find_process(view, c)
        if not procs:
            continue  # the IOC rule still reports the connection itself
        # Prefer the indicator the analyst trusts most.
        o, ioc = max(hits, key=lambda h: _CONF_ORDER.index(h[1].confidence))
        image = c.data.get("image") or c.data.get("exe") or procs[0].data.get("image") \
            or procs[0].data.get("exe")
        key = (host_key(c.host), o.value, (image or "").lower())
        g = groups.setdefault(key, {"conns": [], "procs": {}, "ioc": ioc, "obs": o,
                                    "how": how, "image": image, "host": c.host})
        g["conns"].append(c)
        for p in procs:
            g["procs"][p.id] = p
    out = []
    for _, g in sorted(groups.items()):
        ioc, o, c0 = g["ioc"], g["obs"], g["conns"][0]
        port = c0.data.get("destination_port") or c0.data.get("remote_port")
        rationale = (f"{name_of(g['image'])} on {g['host']} connected to {o.value}"
                     f"{':' + str(port) if port else ''}, which is in IOC list {ioc.source} "
                     f"(confidence {ioc.confidence.value}). The connection was linked to its "
                     f"process by {g['how']} ({len(g['conns'])} connection record(s), "
                     f"{len(g['procs'])} process record(s)).")
        keys = {o}
        for p in g["procs"].values():
            keys |= {x for x in p.observables if x.type.value in ("sha256", "sha1", "md5", "path")}
        out.append(RuleResult(
            _finding(view, "R2", f"{name_of(g['image'])} connected to known indicator {o.value}",
                     FindingCategory.SUSPICIOUS, max_severity([_CONF_TO_SEV[ioc.confidence],
                                                               Severity.HIGH]),
                     ioc.confidence, rationale,
                     [c.id for c in g["conns"]] + list(g["procs"])),
            keys=keys))
    return out


# --------------------------------------------------------------------------- #
# R3 — YARA-matched file executed
# --------------------------------------------------------------------------- #


def rule_flagged_file_executed(view: CaseView) -> list[RuleResult]:
    procs = view.kind(EvidenceKind.PROCESS)
    out = []
    seen: set[tuple[str, str]] = set()
    for y in view.kind(EvidenceKind.YARA_MATCH):
        sha, path = _obs(y, "sha256"), _obs(y, "path")
        by_hash = [p for p in procs if host_key(p.host) == host_key(y.host) and _obs(p, "sha256") & sha]
        by_path = [p for p in procs if host_key(p.host) == host_key(y.host) and _obs(p, "path") & path
                   and p not in by_hash]
        if not by_hash and not by_path:
            continue
        key = (host_key(y.host), next(iter(sha), "") or next(iter(path), ""))
        if key in seen:
            continue
        seen.add(key)
        how = "the same SHA-256 hash" if by_hash else "the same file path (hash not available)"
        conf = Confidence.HIGH if by_hash else Confidence.MEDIUM
        first = min(by_hash + by_path, key=lambda x: (x.event_time is None, x.event_time))
        rationale = (f"{name_of(y.data.get('path'))} matched YARA rule '{y.data.get('rule')}' and "
                     f"was run as a process on {y.host} (first seen {fmt_time(first.event_time)}). "
                     f"File and process were linked by {how}.")
        out.append(RuleResult(
            _finding(view, "R3", f"YARA-flagged file was executed: {name_of(y.data.get('path'))}",
                     FindingCategory.SUSPICIOUS, Severity.HIGH, conf, rationale,
                     [y.id] + [p.id for p in by_hash + by_path]),
            keys=_file_keys(y)))
    return out


# --------------------------------------------------------------------------- #
# R4 — pivot: a finding's key indicator seen in another source or event type
# --------------------------------------------------------------------------- #


def _pivot_ok(view: CaseView, o: Observable) -> bool:
    if o.type.value not in PIVOT_TYPES:
        return False
    if o.type.value == "ip":
        addr = ipaddress.ip_address(o.value)
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or o.value in view.own_ips:
            return False
    return True


# How much one shared indicator is worth (R4). Two things decide it:
# 1. Independence — confirmation by a second, independent source is the
#    strongest level of the Admiralty / NATO credibility scale (FM 2-22.3).
# 2. Indicator type — an exact hash means the same file; an IP address can be
#    shared (NAT) or reassigned (DHCP) (NIST SP 800-86 §6.4.4), and domains
#    and paths can be shared too (e.g. C:\Windows\System32\svchost.exe).
# A repeat of the same kind of event from the same source is not a link
# (as in Splunk RBA, which counts distinct sources, not repeats).
HASH_TYPES = ("sha256", "sha1", "md5")
PIVOT_CONFIDENCE = {
    # (exact hash?, independent source?) -> confidence
    (True, True): Confidence.HIGH,
    (True, False): Confidence.MEDIUM,
    (False, True): Confidence.MEDIUM,
    (False, False): Confidence.LOW,
}
_WHY = {
    True: "an exact hash match means the same file",
    False: "an address, domain or path can be shared by different machines or programs",
}


def _describe(view: CaseView, ids: list[str]) -> str:
    kinds = Counter(f"{view.by_id[x].kind.value.replace('_', ' ')} from "
                    f"{view.by_id[x].source_module.value}" for x in ids)
    refs = ", ".join(ids[:5]) + ("…" if len(ids) > 5 else "")
    return f"{', '.join(f'{n} {k}' for k, n in kinds.items())} ({refs})"


def rule_pivot(view: CaseView, stored: list[tuple[Finding, set[Observable]]]) -> list[Finding]:
    out = []
    reported: set[tuple[Observable, frozenset[str]]] = set()
    for f, keys in stored:
        # Evidence already joined to this finding by another rule (e.g. R3
        # linking a YARA match to its process) is not reported again.
        mine = set(f.evidence_ids)
        in_finding = set(mine)
        for other, _ in stored:
            if mine & set(other.evidence_ids):
                in_finding |= set(other.evidence_ids)
        lines, linked = [], []
        any_independent = False
        best = Confidence.LOW
        notes: set[bool] = set()
        for k in sorted(keys, key=lambda x: (x.type.value, x.value)):
            if not _pivot_ok(view, k):
                continue
            origin = [x for x in f.evidence_ids if k in view.by_id[x].observables]
            if not origin:
                continue
            origin_modules = {view.by_id[x].source_module for x in origin}
            origin_kinds = {(view.by_id[x].source_module, view.by_id[x].kind) for x in origin}
            origin_timed = any(view.by_id[x].event_time for x in origin)
            indep, other_kind = [], []
            for x in dict.fromkeys(view.by_obs.get((k.type.value, k.value), [])):
                e = view.by_id[x]
                if x in in_finding or e.kind is EvidenceKind.INTERFACE:
                    continue
                if e.source_module not in origin_modules:
                    indep.append(x)          # a different tool saw it
                elif ((e.source_module, e.kind) not in origin_kinds
                      and origin_timed and e.event_time is not None):
                    other_kind.append(x)     # same tool, a different kind of event
                # Not links: the same kind of event again (a repeat), or two
                # records that describe one object rather than two events in
                # time (e.g. a file's hash record and its YARA match).
            new = indep + other_kind
            if not new or (k, frozenset(new)) in reported:
                continue  # nothing new, or the same link was reported from another finding
            reported.add((k, frozenset(new)))
            any_independent = any_independent or bool(indep)
            exact = k.type.value in HASH_TYPES
            notes.add(exact)
            for group, label, independent in ((indep, "independent source", True),
                                              (other_kind, "same source, different event type",
                                               False)):
                if group:
                    conf = PIVOT_CONFIDENCE[(exact, independent)]
                    best = max(best, conf, key=_CONF_ORDER.index)
                    lines.append(f"{k.type.value} {short(k.value, 70)} also appears in "
                                 f"{_describe(view, group)} — {label}, confidence {conf.value}")
            linked += origin + new
        if not linked:
            continue
        rationale = (f"Starting from {f.id} ({f.title}): " + "; ".join(lines) + ". "
                     + "; ".join(_WHY[n] for n in sorted(notes, reverse=True)).capitalize()
                     + ". A link confirmed by a second, independent tool is stronger than one "
                     "from a single source. The shared indicator does not by itself prove "
                     "this is the same activity.")
        out.append(_finding(view, "R4",
                            f"Indicator from {f.id} found in "
                            f"{'other sources' if any_independent else 'other events'}",
                            FindingCategory.CORRELATED, Severity.MEDIUM, best,
                            rationale, linked))
    return out


# --------------------------------------------------------------------------- #
# R5 — cluster of suspicious findings on one host
# --------------------------------------------------------------------------- #


def finding_time_and_host(view: CaseView, f: Finding) -> tuple[datetime | None, str | None]:
    evs = [view.by_id[x] for x in f.evidence_ids if x in view.by_id]
    times = [e.event_time for e in evs if e.event_time]
    hosts = Counter(e.host for e in evs)
    return (min(times) if times else None), (hosts.most_common(1)[0][0] if hosts else None)


def rule_cluster(view: CaseView, findings: list[Finding], cfg: CorrelationConfig) -> list[Finding]:
    window = timedelta(minutes=cfg.r5_window_minutes)
    per_host: dict[str, list[tuple[datetime, Finding, str]]] = defaultdict(list)
    for f in findings:
        if f.category is not FindingCategory.SUSPICIOUS:
            continue
        t, host = finding_time_and_host(view, f)
        if t and host:
            per_host[host_key(host)].append((t, f, host))
    out = []
    for _, items in sorted(per_host.items()):
        items.sort(key=lambda x: x[0])
        i = 0
        while i < len(items):
            j = i
            while j + 1 < len(items) and items[j + 1][0] - items[i][0] <= window:
                j += 1
            group = items[i:j + 1]
            if len({g[1].id for g in group}) >= cfg.r5_min_findings:
                host = group[0][2]
                listed = "; ".join(f"{g[1].id} {g[1].title} ({fmt_time(g[0])})" for g in group)
                rationale = (f"{len(group)} suspicious findings on {host} within "
                             f"{cfg.r5_window_minutes} minutes: {listed}. Activity this close "
                             f"together may be one intrusion. This is a hypothesis to "
                             f"investigate, not a confirmed incident.")
                ev = [x for g in group for x in g[1].evidence_ids]
                out.append(_finding(view, "R5", f"Possible coordinated activity on {host}",
                                    FindingCategory.HYPOTHESIS,
                                    max_severity(g[1].severity for g in group),
                                    Confidence.MEDIUM, rationale, ev))
                i = j + 1
            else:
                i += 1
    return out
