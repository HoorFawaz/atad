# Copyright (C) 2026 Hoor Fawaz
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

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
    Execution,
    Finding,
    Ioc,
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
        return self.add_evidence_many([ev])[0]

    def add_evidence_many(self, items: list[Evidence]) -> list[Evidence]:
        """Store many evidence records in one transaction (all or nothing)."""
        for ev in items:
            if ev.id is not None:
                raise ValidationError("evidence already has an id; ids are assigned on insert")
        if not items:
            return []
        stored: list[Evidence] = []
        with self.connect() as conn:
            n = conn.execute(
                "SELECT COALESCE(MAX(CAST(SUBSTR(id, 5) AS INTEGER)), 0) FROM evidence"
            ).fetchone()[0]
            for i, ev in enumerate(items, start=1):
                ev_id = f"EVD-{n + i:06d}"
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
                stored.append(ev.model_copy(update={"id": ev_id}))
        return stored

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

    def list_evidence(self, kinds: list[str] | None = None) -> list[Evidence]:
        """All evidence, or only the given kinds (e.g. ["logon", "process"])."""
        with self.connect() as conn:
            if kinds:
                marks = ",".join("?" * len(kinds))
                rows = conn.execute(
                    f"SELECT * FROM evidence WHERE kind IN ({marks}) ORDER BY id", kinds
                ).fetchall()
                obs_rows = conn.execute(
                    "SELECT o.evidence_id, o.type, o.value FROM observables o"
                    f" JOIN evidence e ON e.id = o.evidence_id WHERE e.kind IN ({marks})", kinds
                ).fetchall()
            else:
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
        return self.add_findings_many([f])[0]

    def add_findings_many(self, items: list[Finding]) -> list[Finding]:
        """Store findings and their evidence links in one transaction."""
        for f in items:
            if f.id is not None:
                raise ValidationError("finding already has an id; ids are assigned on insert")
        if not items:
            return []
        stored: list[Finding] = []
        with self.connect() as conn:
            for f in items:
                for ev_id in f.evidence_ids:
                    if conn.execute("SELECT 1 FROM evidence WHERE id = ?", (ev_id,)).fetchone() is None:
                        raise ValidationError(f"finding references unknown evidence {ev_id}")
            # Numbers continue from the highest id ever used, so ids are never
            # reused after findings are regenerated.
            n = max(
                conn.execute(
                    "SELECT COALESCE(MAX(CAST(SUBSTR(id, 5) AS INTEGER)), 0) FROM findings"
                ).fetchone()[0],
                int(self._meta(conn, "last_finding_number") or 0),
            )
            for i, f in enumerate(items, start=1):
                f_id = f"FND-{n + i:04d}"
                conn.execute(
                    "INSERT INTO findings(id, case_id, title, description, category, severity,"
                    " confidence, rule_id, rationale, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (f_id, f.case_id, f.title, f.description, f.category.value, f.severity.value,
                     f.confidence.value, f.rule_id, f.rationale, _ts(f.created_at)),
                )
                conn.executemany(
                    "INSERT INTO finding_evidence(finding_id, evidence_id) VALUES (?,?)",
                    [(f_id, e) for e in dict.fromkeys(f.evidence_ids)],
                )
                stored.append(f.model_copy(update={"id": f_id}))
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('last_finding_number', ?)",
                (str(n + len(items)),),
            )
        return stored

    def delete_findings_by_rules(self, rule_ids: list[str]) -> int:
        """Remove findings produced by these rules (before re-running them)."""
        if not rule_ids:
            return 0
        marks = ",".join("?" * len(rule_ids))
        with self.connect() as conn:
            conn.execute(
                f"DELETE FROM timeline_events WHERE finding_id IN"
                f" (SELECT id FROM findings WHERE rule_id IN ({marks}))", rule_ids)
            cur = conn.execute(f"DELETE FROM findings WHERE rule_id IN ({marks})", rule_ids)
            return cur.rowcount

    @staticmethod
    def _meta(conn: sqlite3.Connection, key: str) -> str | None:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

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

    # ------------------------------------------------------------- executions

    def add_execution(self, ex: Execution) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO executions(case_id, module, tool, tool_version, command, target,"
                " collection_mode, started_at, finished_at, status, exit_code, raw_ref,"
                " raw_sha256, stderr_excerpt, error, elevated)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                self._execution_values(ex),
            )
            return int(cur.lastrowid)

    def finish_execution(self, ex: Execution) -> None:
        if ex.id is None:
            raise ValidationError("execution has no id")
        with self.connect() as conn:
            conn.execute(
                "UPDATE executions SET case_id=?, module=?, tool=?, tool_version=?, command=?,"
                " target=?, collection_mode=?, started_at=?, finished_at=?, status=?,"
                " exit_code=?, raw_ref=?, raw_sha256=?, stderr_excerpt=?, error=?, elevated=?"
                " WHERE id=?",
                (*self._execution_values(ex), ex.id),
            )

    def list_executions(self) -> list[Execution]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM executions ORDER BY id").fetchall()
        return [
            Execution(
                id=r["id"],
                case_id=r["case_id"],
                module=r["module"],
                tool=r["tool"],
                tool_version=r["tool_version"],
                command=json.loads(r["command"]) if r["command"] else None,
                target=r["target"],
                collection_mode=r["collection_mode"],
                started_at=_dt(r["started_at"]),
                finished_at=_dt(r["finished_at"]),
                status=r["status"],
                exit_code=r["exit_code"],
                raw_ref=r["raw_ref"],
                raw_sha256=r["raw_sha256"],
                stderr_excerpt=r["stderr_excerpt"],
                error=r["error"],
                elevated=None if r["elevated"] is None else bool(r["elevated"]),
            )
            for r in rows
        ]

    @staticmethod
    def _execution_values(ex: Execution) -> tuple:
        return (
            ex.case_id,
            ex.module.value,
            ex.tool,
            ex.tool_version,
            json.dumps(ex.command) if ex.command is not None else None,
            ex.target,
            ex.collection_mode.value,
            _ts(ex.started_at),
            _ts(ex.finished_at),
            ex.status.value,
            ex.exit_code,
            ex.raw_ref,
            ex.raw_sha256,
            ex.stderr_excerpt,
            ex.error,
            None if ex.elevated is None else int(ex.elevated),
        )

    # ------------------------------------------------------------------ tools

    def record_tool(
        self,
        name: str,
        *,
        available: bool,
        version: str | None,
        path: str | None,
        reason: str | None,
        detected_at: datetime,
    ) -> None:
        case_id = self.get_case().id
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO tools(case_id, name, version, path, available, reason, detected_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (case_id, name, version, path, int(available), reason, _ts(detected_at)),
            )

    def list_tools(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM tools ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------------- iocs

    def add_iocs(self, iocs: list[Ioc]) -> int:
        """Store indicators; duplicates (same type, value and source) are ignored."""
        with self.connect() as conn:
            before = conn.total_changes
            conn.executemany(
                "INSERT OR IGNORE INTO iocs(case_id, type, value, source, confidence, description,"
                " added_at) VALUES (?,?,?,?,?,?,?)",
                [(i.case_id, i.type, i.value, i.source, i.confidence.value, i.description,
                  _ts(i.added_at)) for i in iocs],
            )
            return conn.total_changes - before

    def list_iocs(self) -> list[Ioc]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM iocs ORDER BY id").fetchall()
        return [Ioc(id=r["id"], case_id=r["case_id"], type=r["type"], value=r["value"],
                    source=r["source"], confidence=r["confidence"], description=r["description"],
                    added_at=_dt(r["added_at"])) for r in rows]

    def match_iocs_exact(self) -> list[sqlite3.Row]:
        """(ioc row, evidence_id) pairs where an observable equals an indicator."""
        with self.connect() as conn:
            return conn.execute(
                "SELECT i.id AS ioc_id, i.type, i.value, o.evidence_id FROM iocs i"
                " JOIN observables o ON o.type = i.type AND o.value = i.value"
                " ORDER BY i.id, o.evidence_id"
            ).fetchall()

    def observables_of_type(self, kind: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT evidence_id, value FROM observables WHERE type = ?", (kind,)
            ).fetchall()

    # ---------------------------------------------------------------- timeline

    def replace_timeline(self, events: list[dict]) -> int:
        """Rebuild the case timeline from scratch."""
        with self.connect() as conn:
            conn.execute("DELETE FROM timeline_events")
            conn.executemany(
                "INSERT INTO timeline_events(case_id, event_time, host, description, evidence_id,"
                " finding_id) VALUES (:case_id, :event_time, :host, :description, :evidence_id,"
                " :finding_id)",
                events,
            )
        return len(events)

    def list_timeline(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM timeline_events ORDER BY event_time, id"
            ).fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------------------- counts

    def counts(self) -> dict[str, int]:
        tables = ("targets", "executions", "evidence", "findings", "iocs", "reports")
        with self.connect() as conn:
            return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
