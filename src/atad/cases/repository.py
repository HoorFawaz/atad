"""SQLite access for one case database.

All SQL lives here. Other modules work with the Pydantic models from
``atad.evidence.models`` and never build queries themselves.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Iterator

from atad.core.exceptions import StorageError, ValidationError
from atad.evidence.models import (
    Case,
    Evidence,
    Finding,
    Observable,
    Target,
)

SCHEMA_VERSION = "1"


def _ts(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _dt(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


class CaseRepository:
    """Read/write access to ``case.db`` for a single case."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    # ------------------------------------------------------------------ setup

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        try:
            conn = sqlite3.connect(self.db_path)
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open case database {self.db_path}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise StorageError(f"database integrity error: {exc}") from exc
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        schema = resources.files("atad.cases").joinpath("schema.sql").read_text(encoding="utf-8")
        with self.connect() as conn:
            conn.executescript(schema)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,),
            )

    # ------------------------------------------------------------------- case

    def insert_case(self, case: Case) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO cases(id, name, profile, description, simulated, created_at, atad_version)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    case.id,
                    case.name,
                    case.profile.value,
                    case.description,
                    int(case.simulated),
                    _ts(case.created_at),
                    case.atad_version,
                ),
            )

    def get_case(self) -> Case:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM cases LIMIT 1").fetchone()
        if row is None:
            raise StorageError(f"no case record in {self.db_path}")
        return Case(
            id=row["id"],
            name=row["name"],
            profile=row["profile"],
            description=row["description"],
            simulated=bool(row["simulated"]),
            created_at=_dt(row["created_at"]),
            atad_version=row["atad_version"],
        )

    # ---------------------------------------------------------------- targets

    def add_target(self, target: Target) -> bool:
        """Add a scope entry. Returns False if it was already in scope."""
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO targets(case_id, value, kind, is_public, added_at, note)"
                " VALUES (?,?,?,?,?,?)",
                (
                    target.case_id,
                    target.value,
                    target.kind,
                    int(target.is_public),
                    _ts(target.added_at),
                    target.note,
                ),
            )
            return cur.rowcount == 1

    def list_targets(self) -> list[Target]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM targets ORDER BY id").fetchall()
        return [
            Target(
                case_id=r["case_id"],
                value=r["value"],
                kind=r["kind"],
                is_public=bool(r["is_public"]),
                added_at=_dt(r["added_at"]),
                note=r["note"],
            )
            for r in rows
        ]

    # --------------------------------------------------------------- evidence

    def add_evidence(self, ev: Evidence) -> Evidence:
        """Store evidence and its observables; returns it with its new id."""
        if ev.id is not None:
            raise ValidationError("evidence already has an id; ids are assigned on insert")
        with self.connect() as conn:
            n = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            ev_id = f"EVD-{n + 1:06d}"
            conn.execute(
                "INSERT INTO evidence(id, case_id, kind, source_module, source_tool, tool_version,"
                " collection_mode, host, host_declared, collected_at, event_time, execution_id,"
                " raw_ref, raw_sha256, summary, data, simulated, status)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ev_id,
                    ev.case_id,
                    ev.kind.value,
                    ev.source_module.value,
                    ev.source_tool,
                    ev.tool_version,
                    ev.collection_mode.value,
                    ev.host,
                    int(ev.host_declared),
                    _ts(ev.collected_at),
                    _ts(ev.event_time),
                    ev.execution_id,
                    ev.raw_ref,
                    ev.raw_sha256,
                    ev.summary,
                    json.dumps(ev.data, ensure_ascii=False, sort_keys=True, default=str),
                    int(ev.simulated),
                    ev.status.value,
                ),
            )
            conn.executemany(
                "INSERT OR IGNORE INTO observables(evidence_id, type, value) VALUES (?,?,?)",
                [(ev_id, o.type.value, o.value) for o in ev.observables],
            )
        return ev.model_copy(update={"id": ev_id})

    def get_evidence(self, evidence_id: str) -> Evidence:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
            if row is None:
                raise StorageError(f"evidence {evidence_id} not found")
            obs = conn.execute(
                "SELECT type, value FROM observables WHERE evidence_id = ? ORDER BY type, value",
                (evidence_id,),
            ).fetchall()
        return self._row_to_evidence(row, obs)

    def list_evidence(self) -> list[Evidence]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM evidence ORDER BY id").fetchall()
            obs_rows = conn.execute("SELECT evidence_id, type, value FROM observables").fetchall()
        by_ev: dict[str, list[sqlite3.Row]] = {}
        for o in obs_rows:
            by_ev.setdefault(o["evidence_id"], []).append(o)
        return [self._row_to_evidence(r, by_ev.get(r["id"], [])) for r in rows]

    def find_evidence_by_observable(self, obs: Observable) -> list[str]:
        """Evidence ids that contain the given observable (correlation lookup)."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT evidence_id FROM observables WHERE type = ? AND value = ? ORDER BY evidence_id",
                (obs.type.value, obs.value),
            ).fetchall()
        return [r["evidence_id"] for r in rows]

    @staticmethod
    def _row_to_evidence(row: sqlite3.Row, obs: list[sqlite3.Row]) -> Evidence:
        return Evidence(
            id=row["id"],
            case_id=row["case_id"],
            kind=row["kind"],
            source_module=row["source_module"],
            source_tool=row["source_tool"],
            tool_version=row["tool_version"],
            collection_mode=row["collection_mode"],
            host=row["host"],
            host_declared=bool(row["host_declared"]),
            collected_at=_dt(row["collected_at"]),
            event_time=_dt(row["event_time"]),
            execution_id=row["execution_id"],
            raw_ref=row["raw_ref"],
            raw_sha256=row["raw_sha256"],
            summary=row["summary"],
            data=json.loads(row["data"]),
            observables=[Observable(type=o["type"], value=o["value"]) for o in obs],
            simulated=bool(row["simulated"]),
            status=row["status"],
        )

    # --------------------------------------------------------------- findings

    def add_finding(self, f: Finding) -> Finding:
        if f.id is not None:
            raise ValidationError("finding already has an id; ids are assigned on insert")
        with self.connect() as conn:
            for ev_id in f.evidence_ids:
                if conn.execute("SELECT 1 FROM evidence WHERE id = ?", (ev_id,)).fetchone() is None:
                    raise ValidationError(f"finding references unknown evidence {ev_id}")
            n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            f_id = f"FND-{n + 1:04d}"
            conn.execute(
                "INSERT INTO findings(id, case_id, title, description, category, severity,"
                " confidence, rule_id, rationale, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    f_id,
                    f.case_id,
                    f.title,
                    f.description,
                    f.category.value,
                    f.severity.value,
                    f.confidence.value,
                    f.rule_id,
                    f.rationale,
                    _ts(f.created_at),
                ),
            )
            conn.executemany(
                "INSERT INTO finding_evidence(finding_id, evidence_id) VALUES (?,?)",
                [(f_id, e) for e in f.evidence_ids],
            )
        return f.model_copy(update={"id": f_id})

    def list_findings(self) -> list[Finding]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
            links = conn.execute(
                "SELECT finding_id, evidence_id FROM finding_evidence ORDER BY evidence_id"
            ).fetchall()
        ev_map: dict[str, list[str]] = {}
        for link in links:
            ev_map.setdefault(link["finding_id"], []).append(link["evidence_id"])
        return [
            Finding(
                id=r["id"],
                case_id=r["case_id"],
                title=r["title"],
                description=r["description"],
                category=r["category"],
                severity=r["severity"],
                confidence=r["confidence"],
                rule_id=r["rule_id"],
                rationale=r["rationale"],
                evidence_ids=ev_map.get(r["id"], []),
                created_at=_dt(r["created_at"]),
            )
            for r in rows
        ]

    # ----------------------------------------------------------------- counts

    def counts(self) -> dict[str, int]:
        tables = ("targets", "executions", "evidence", "findings", "iocs", "reports")
        with self.connect() as conn:
            return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
