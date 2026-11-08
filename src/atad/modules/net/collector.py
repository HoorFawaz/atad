# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Network checks: interfaces, ping, Nmap and DNS.

Design notes
* Interfaces come from psutil and DNS from the system resolver, not from
  parsing ``ipconfig`` / ``nslookup`` text, because that text changes with the
  Windows display language (e.g. Arabic Windows).
* Ping reachability uses the exit code AND a ``TTL=`` reply line, because
  Windows ``ping`` can exit 0 when a router answers "destination unreachable".
* Nmap runs only with fixed, safe profiles (TCP connect scan, no scripts).
* On Linux the interface check also reads the routing table (``ip -j route``,
  JSON output) and DNS adds MX/NS/TXT/CNAME records with ``dig`` when it is
  installed.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import socket
import xml.etree.ElementTree as ET
from typing import Any

from atad.adapters.base import ParseContext
from atad.core.exceptions import ValidationError
from atad.evidence.models import Evidence, EvidenceKind, Observable, SourceModule
from atad.modules.common import base_fields

# ----------------------------------------------------------------- interfaces


def collect_interfaces() -> dict[str, Any]:
    import psutil

    stats = psutil.net_if_stats()
    records = []
    for name, addrs in sorted(psutil.net_if_addrs().items()):
        st = stats.get(name)
        out = []
        for a in addrs:
            if a.family == socket.AF_INET:
                fam = "ipv4"
            elif a.family == socket.AF_INET6:
                fam = "ipv6"
            else:
                fam = "mac"
            out.append({"family": fam, "address": a.address, "netmask": a.netmask})
        records.append({
            "name": name, "is_up": st.isup if st else None, "speed_mbps": st.speed if st else None,
            "mtu": st.mtu if st else None, "addresses": out,
        })
    cap: dict[str, Any] = {"check": "interfaces", "count": len(records), "records": records}
    routes = collect_routes()
    if routes is not None:
        cap["routes"] = routes
    return cap


def collect_routes() -> dict[str, Any] | None:
    """Linux routing table from ``ip -j route`` (None where ``ip`` is not available)."""
    from atad.core.execution import resolve_executable, run_command
    from atad.core.platform import LINUX, current_os

    if current_os() != LINUX:
        return None
    ip = resolve_executable("ip")
    if not ip:
        return {"error": "ip command not found", "entries": []}
    res = run_command([ip, "-j", "route", "show"], timeout=10, max_output=1024 * 1024)
    if not res.ok:
        return {"error": (res.error or res.stderr.decode("utf-8", "replace"))[:200], "entries": []}
    try:
        entries = json.loads(res.stdout or b"[]")
    except ValueError:
        return {"error": "ip -j route did not return JSON", "entries": []}
    return {"error": None, "command": [ip, "-j", "route", "show"],
            "entries": [{k: e.get(k) for k in ("dst", "gateway", "dev", "protocol", "prefsrc", "metric")}
                        for e in entries if isinstance(e, dict)]}


def interfaces_to_evidence(cap: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for r in cap["records"]:
        ips = [a["address"] for a in r["addresses"] if a["family"] in ("ipv4", "ipv6")]
        obs = []
        for ip in ips:
            try:
                obs.append(Observable(type="ip", value=ip.split("%")[0]))
            except ValueError:
                pass
        state = "up" if r["is_up"] else "down"
        out.append(Evidence(
            **base_fields(ctx, SourceModule.NET, "psutil"), kind=EvidenceKind.INTERFACE,
            summary=f"Interface {r['name']} ({state}): {', '.join(ips) or 'no IP'}",
            data=r, observables=obs,
        ))
    routes = cap.get("routes")
    if routes and routes.get("entries"):
        # Gateways are not this machine's addresses, so they are kept out of the
        # INTERFACE records (which correlation treats as "own" addresses).
        default = [e for e in routes["entries"] if e.get("dst") == "default"]
        gw = ", ".join(f"{e.get('gateway')} dev {e.get('dev')}" for e in default) or "none"
        obs = []
        for e in default:
            try:
                obs.append(Observable(type="ip", value=e["gateway"]))
            except (ValueError, KeyError, TypeError):
                pass
        out.append(Evidence(
            **base_fields(ctx, SourceModule.NET, "ip route"), kind=EvidenceKind.HOST_INFO,
            summary=f"Routing table: {len(routes['entries'])} route(s); default via {gw}",
            data=routes, observables=obs))
    return out


# ----------------------------------------------------------------------- ping

PING_COUNT = 4
_TTL = re.compile(rb"ttl[=:]\s*(\d+)", re.IGNORECASE)
_TIME = re.compile(rb"time([=<])\s*([\d.]+)\s*ms", re.IGNORECASE)


def build_ping_args(exe: str, target: str, os_name: str, count: int = PING_COUNT) -> list[str]:
    if os_name == "windows":
        return [exe, "-n", str(count), "-w", "1000", target]
    return [exe, "-c", str(count), "-W", "1", target]


def parse_ping(stdout: bytes, exit_code: int | None, target: str) -> dict[str, Any]:
    ttls = [int(x) for x in _TTL.findall(stdout)]
    found = _TIME.findall(stdout)
    # "time<1ms" only says "under 1 ms", so it is not averaged as a number.
    times = [float(v) for op, v in found if op == b"="]
    reachable = exit_code == 0 and bool(ttls)
    return {
        "target": target, "reachable": reachable, "replies": len(ttls),
        "ttl": ttls[0] if ttls else None,
        "avg_ms": round(sum(times) / len(times), 2) if times else None,
        "replies_under_1ms": sum(1 for op, _ in found if op == b"<"),
        "exit_code": exit_code,
    }


def ping_to_evidence(result: dict, ctx: ParseContext) -> list[Evidence]:
    t = result["target"]
    obs = []
    try:
        obs.append(Observable(type="ip", value=t))
    except ValueError:
        obs.append(Observable(type="hostname", value=t))
    if result["reachable"]:
        summary = f"{t} replied to ping ({result['replies']}/{PING_COUNT}, TTL {result['ttl']}"
        summary += f", avg {result['avg_ms']} ms)" if result["avg_ms"] is not None else ")"
    else:
        summary = f"{t} did not reply to ping (it may still be up behind a firewall)"
    return [Evidence(**base_fields(ctx, SourceModule.NET, "ping"), kind=EvidenceKind.PING,
                     summary=summary, data=result, observables=obs)]


# ----------------------------------------------------------------------- nmap

NMAP_PROFILES = {
    # TCP connect scan: works without admin rights, no raw packets.
    "quick": ["-sT", "-T3", "-F", "--open"],
    "standard": ["-sT", "-sV", "--version-light", "-T3", "--top-ports", "1000", "--open"],
}
_PORTS = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


def validate_ports(ports: str) -> str:
    p = ports.replace(" ", "")
    if not _PORTS.match(p):
        raise ValidationError(f"invalid port list {ports!r} (example: 22,80,443,8000-8100)")
    for part in p.split(","):
        lo, _, hi = part.partition("-")
        a, b = int(lo), int(hi or lo)
        if not (1 <= a <= 65535 and 1 <= b <= 65535 and a <= b):
            raise ValidationError(f"port out of range in {ports!r}")
    return p


def build_nmap_args(exe: str, targets: list[str], profile: str = "standard",
                    ports: str | None = None, single_host: bool = True) -> list[str]:
    if profile not in NMAP_PROFILES:
        raise ValidationError(f"unknown scan profile {profile!r} (use: {', '.join(NMAP_PROFILES)})")
    args = [exe, *NMAP_PROFILES[profile]]
    if ports:
        # Explicit ports replace the profile's port selection.
        args = [a for a in args if a not in ("-F", "--top-ports", "1000")]
        args += ["-p", validate_ports(ports)]
    if single_host:
        args.append("-Pn")  # host may block ping; scan anyway
    args += ["-oX", "-", *targets]
    for t in targets:
        if t.startswith("-"):
            raise ValidationError(f"invalid target {t!r}")
    return args


def parse_nmap_xml(raw: bytes) -> dict[str, Any]:
    root = ET.fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError("not Nmap XML output")
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        addrs = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "protocol": p.get("protocol"), "port": int(p.get("portid")),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
            })
        hosts.append({
            "ip": addrs.get("ipv4") or addrs.get("ipv6"), "mac": addrs.get("mac"),
            "hostnames": names, "state": status.get("state") if status is not None else None,
            "open_ports": ports,
        })
    finished = root.find("runstats/finished")
    return {
        "nmap_version": root.get("version"), "args": root.get("args"),
        "elapsed_s": float(finished.get("elapsed")) if finished is not None and finished.get("elapsed") else None,
        "hosts": hosts,
    }


def nmap_to_evidence(parsed: dict, ctx: ParseContext) -> list[Evidence]:
    out = []
    for h in parsed["hosts"]:
        if h["state"] != "up" or not h["ip"]:
            continue
        host_obs = [Observable(type="ip", value=h["ip"])] + [
            Observable(type="hostname", value=n) for n in h["hostnames"]]
        name = f" ({h['hostnames'][0]})" if h["hostnames"] else ""
        b = base_fields(ctx, SourceModule.NET, "nmap") | {"host": h["ip"]}
        out.append(Evidence(**b, kind=EvidenceKind.HOST_INFO,
                            summary=f"Host up: {h['ip']}{name}, {len(h['open_ports'])} open port(s)",
                            data=h, observables=host_obs))
        for p in h["open_ports"]:
            svc = " ".join(x for x in (p["product"], p["version"]) if x) or p["service"] or "unknown"
            out.append(Evidence(**b, kind=EvidenceKind.OPEN_PORT,
                                summary=f"{h['ip']}:{p['port']}/{p['protocol']} open — {svc}",
                                data={"ip": h["ip"], **p}, observables=host_obs))
    return out


# ------------------------------------------------------------------------ dns

DNS_TIMEOUT = 10


def _with_timeout(fn, *args):
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(fn, *args).result(timeout=DNS_TIMEOUT)
    finally:
        pool.shutdown(wait=False)


def resolve_name(name: str) -> list[str]:
    infos = _with_timeout(socket.getaddrinfo, name, None)
    return sorted({i[4][0] for i in infos})


DIG_TYPES = ("MX", "NS", "TXT", "CNAME")


def dig_records(name: str) -> dict[str, list[str]] | None:
    """Extra record types with ``dig +short`` (None when dig is not installed)."""
    from atad.core.execution import resolve_executable, run_command

    dig = resolve_executable("dig")
    if not dig:
        return None
    out: dict[str, list[str]] = {}
    for rtype in DIG_TYPES:
        res = run_command([dig, "+short", "+time=2", "+tries=1", name, rtype],
                          timeout=8, max_output=256 * 1024)
        lines = [ln.strip() for ln in res.stdout.decode("utf-8", "replace").splitlines()
                 if ln.strip() and not ln.startswith(";")] if res.ok else []
        if lines:
            out[rtype] = lines
    return out


def collect_dns(target: str) -> dict[str, Any]:
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False
    rec: dict[str, Any] = {"check": "dns", "query": target,
                           "type": "reverse (PTR)" if is_ip else "forward (A/AAAA)"}
    try:
        if is_ip:
            name, aliases, _ = _with_timeout(socket.gethostbyaddr, target)
            rec["answers"] = [name, *aliases]
        else:
            rec["answers"] = resolve_name(target)
            extra = dig_records(target)
            if extra is not None:
                rec["records"] = extra
        rec["error"] = None
    except concurrent.futures.TimeoutError:
        rec["answers"], rec["error"] = [], f"no answer within {DNS_TIMEOUT}s"
    except OSError as exc:
        rec["answers"], rec["error"] = [], f"no record ({exc.strerror or exc})"
    return rec


def dns_to_evidence(cap: dict, ctx: ParseContext) -> list[Evidence]:
    q = cap["query"]
    obs: list[Observable] = []
    for v in [q, *cap["answers"]]:
        try:
            obs.append(Observable(type="ip", value=v))
        except ValueError:
            obs.append(Observable(type="domain", value=v))
    for rtype, values in (cap.get("records") or {}).items():
        if rtype in ("MX", "NS", "CNAME"):
            for v in values:
                host = v.split()[-1].rstrip(".")
                try:
                    obs.append(Observable(type="domain", value=host))
                except ValueError:
                    pass
    if cap["answers"]:
        summary = f"DNS {cap['type']}: {q} -> {', '.join(cap['answers'])}"
    else:
        summary = f"DNS {cap['type']}: {q} — {cap['error']}"
    if cap.get("records"):
        summary += " (" + "; ".join(f"{k} {len(v)}" for k, v in cap["records"].items()) + ", via dig)"
    return [Evidence(**base_fields(ctx, SourceModule.NET, "system resolver"),
                     kind=EvidenceKind.DNS_RECORD, summary=summary, data=cap, observables=obs)]
