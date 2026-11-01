"""Shared data models used by every atad module.

These models are the contract between collectors, the database, the
correlation engine and the reports. Source-specific details go in
``Evidence.data``; anything used to link evidence together goes in
``Evidence.observables``.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as aware UTC. Naive datetimes are rejected.

    Naive times are the main cause of wrong correlations across sources,
    so atad refuses them instead of guessing a timezone.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class CollectionMode(str, Enum):
    LOCAL = "local"      # atad runs on the machine it collects from
    IMPORT = "import"    # evidence files copied from another machine
    NETWORK = "network"  # checks against an authorized network target


class SourceModule(str, Enum):
    NET = "net"
    HOST = "host"
    FILES = "files"
    LOG = "log"
    IOC = "ioc"


class EvidenceKind(str, Enum):
    HOST_INFO = "host_info"
    INTERFACE = "interface"
    PROCESS = "process"
    NETWORK_CONNECTION = "network_connection"
    OPEN_PORT = "open_port"
    DNS_RECORD = "dns_record"
    LOGON = "logon"
    LOG_EVENT = "log_event"
    FILE = "file"
    YARA_MATCH = "yara_match"
    IOC_MATCH = "ioc_match"


class EvidenceStatus(str, Enum):
    COLLECTED = "collected"
    PARTIAL = "partial"
    ERROR = "error"


class ExecutionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"          # not run on purpose (profile, platform)
    UNAVAILABLE = "unavailable"  # tool missing or not permitted
    TIMEOUT = "timeout"


class FindingCategory(str, Enum):
    OBSERVATION = "observation"  # confirmed fact
    SUSPICIOUS = "suspicious"    # suspicious indicator
    CORRELATED = "correlated"    # evidence linked across sources
    HYPOTHESIS = "hypothesis"    # needs further investigation


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Profile(str, Enum):
    SOC = "soc"
    DFIR = "dfir"
    FULL = "full"


# --------------------------------------------------------------------------- #
# Observables — the correlation keys
# --------------------------------------------------------------------------- #


class ObservableType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"
    PATH = "path"
    USER = "user"
    HOSTNAME = "hostname"
    PID = "pid"
    PROCESS_GUID = "process_guid"


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")


def normalize_observable(kind: ObservableType, value: str) -> str:
    """Return the canonical form of an observable value.

    The same real-world indicator must always produce the same string,
    otherwise correlation silently misses links.
    """
    v = str(value).strip()
    if not v:
        raise ValueError("observable value is empty")

    if kind is ObservableType.IP:
        return str(ipaddress.ip_address(v))
    if kind in (ObservableType.DOMAIN, ObservableType.HOSTNAME):
        return v.lower().rstrip(".")
    if kind is ObservableType.SHA256:
        v = v.lower()
        if not _HEX64.match(v):
            raise ValueError(f"not a SHA-256 hash: {value!r}")
        return v
    if kind is ObservableType.MD5:
        v = v.lower()
        if not _HEX32.match(v):
            raise ValueError(f"not an MD5 hash: {value!r}")
        return v
    if kind is ObservableType.PATH:
        # Windows paths are case-insensitive; one separator style.
        return v.replace("/", "\\").lower()
    if kind in (ObservableType.USER, ObservableType.PROCESS_GUID):
        return v.lower()
    if kind is ObservableType.PID:
        pid = int(v)
        if pid < 0:
            raise ValueError("pid must be >= 0")
        return str(pid)
    return v  # URL: kept as-is apart from stripping


class Observable(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: ObservableType
    value: str

    @model_validator(mode="after")
    def _normalize(self) -> "Observable":
        object.__setattr__(self, "value", normalize_observable(self.type, self.value))
        return self


# --------------------------------------------------------------------------- #
# Core records
# --------------------------------------------------------------------------- #


class Evidence(BaseModel):
    """One normalized piece of evidence."""

    id: str | None = None                 # assigned by the repository (EVD-000001)
    case_id: str
    kind: EvidenceKind
    source_module: SourceModule
    source_tool: str
    tool_version: str | None = None
    collection_mode: CollectionMode
    host: str
    host_declared: bool = False           # True when typed by the analyst (import mode)
    collected_at: datetime = Field(default_factory=utc_now)
    event_time: datetime | None = None
    execution_id: int | None = None
    raw_ref: str | None = None            # path relative to the case folder
    raw_sha256: str | None = None
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    observables: list[Observable] = Field(default_factory=list)
    simulated: bool = False
    status: EvidenceStatus = EvidenceStatus.COLLECTED

    @field_validator("collected_at", "event_time")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        return None if v is None else ensure_utc(v)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("host is required")
        return v

    @field_validator("raw_sha256")
    @classmethod
    def _sha(cls, v: str | None) -> str | None:
        return None if v is None else normalize_observable(ObservableType.SHA256, v)

    @model_validator(mode="after")
    def _mode_rules(self) -> "Evidence":
        # Local collection must never carry an analyst-typed host name.
        if self.collection_mode is CollectionMode.LOCAL and self.host_declared:
            raise ValueError("local evidence cannot have an analyst-declared host")
        if self.collection_mode is CollectionMode.IMPORT and not self.host_declared:
            raise ValueError("imported evidence must have an analyst-declared host")
        return self


class Finding(BaseModel):
    id: str | None = None                 # FND-0001
    case_id: str
    title: str
    description: str = ""
    category: FindingCategory
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    rule_id: str | None = None
    rationale: str = ""                   # plain-language reason for the link
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @model_validator(mode="after")
    def _needs_evidence(self) -> "Finding":
        # A correlated finding without evidence would be an invented claim.
        if self.category is FindingCategory.CORRELATED and len(self.evidence_ids) < 2:
            raise ValueError("a correlated finding must reference at least 2 evidence records")
        return self


class Case(BaseModel):
    id: str                               # CASE-001
    name: str
    profile: Profile = Profile.SOC
    description: str = ""
    simulated: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    atad_version: str

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("case name is required")
        if len(v) > 200:
            raise ValueError("case name is too long (max 200 characters)")
        return v

    @field_validator("created_at")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        return ensure_utc(v)


class Target(BaseModel):
    """An authorized network target (single IP, CIDR range or hostname)."""

    case_id: str
    value: str                            # normalized by utils.validation
    kind: str                             # ip | cidr | hostname
    is_public: bool = False
    added_at: datetime = Field(default_factory=utc_now)
    note: str = ""
