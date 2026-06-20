"""Case management with SQLite backend."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

log = logging.getLogger(__name__)


@dataclass
class Case:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    analyst: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    status: str = "open"  # open, closed, archived
    notes: str = ""
    db_path: str = ""  # path to case-specific SQLite

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "analyst": self.analyst,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "notes": self.notes,
        }


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    analyst TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    type TEXT NOT NULL,  -- disk, memory, log, other
    path TEXT NOT NULL,
    filename TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    format TEXT DEFAULT '',  -- E01, RAW, VMDK, QCOW2, raw, elf64, etc
    ingested_at TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT,  -- nullable: triage/system artifacts may not reference specific evidence
    source TEXT NOT NULL,  -- filesystem, registry, prefetch, events, memory, hunt, triage
    category TEXT DEFAULT '',
    timestamp TEXT DEFAULT '',
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',  -- info, low, medium, high, critical
    data TEXT DEFAULT '{}',  -- JSON blob
    FOREIGN KEY (case_id) REFERENCES cases(id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);

CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    artifact_id TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS hunt_results (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_type TEXT NOT NULL,  -- yara, ioc, regex
    evidence_id TEXT,
    match_offset INTEGER DEFAULT 0,
    match_data TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    detected_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_case_ts ON timeline(case_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_hunt_case ON hunt_results(case_id);
"""


class CaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrent write handling
        self.conn.execute("PRAGMA journal_mode=WAL")
        # Enable foreign key enforcement
        self.conn.execute("PRAGMA foreign_keys=ON")
        # Busy timeout for concurrent access (5 seconds)
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)

    def __enter__(self) -> CaseManager:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.close()

    # Valid severity values — enforced at the DB boundary (H-7). Prevents
    # arbitrary strings (e.g. from YARA rule metadata) poisoning the triage
    # scorer's severity_counts and the report's CSS classes.
    VALID_SEVERITIES: ClassVar[frozenset[str]] = frozenset(
        {"info", "low", "medium", "high", "critical"}
    )

    @classmethod
    def _normalize_severity(cls, severity: str, default: str = "info") -> str:
        """Return a valid severity, or `default` (with a log warning) if invalid.

        Fail-safe (not fail-closed) for severity because the value often comes
        from external input (YARA rule metadata, IOC feeds). An invalid value
        is normalized to the caller's default and logged, rather than raising
        — so a malformed rule doesn't abort a hunt halfway through.
        """
        if severity in cls.VALID_SEVERITIES:
            return severity
        log.warning("Invalid severity %r — normalizing to %r", severity, default)
        return default

    def create_case(self, name: str, analyst: str = "", notes: str = "") -> Case:
        case = Case(name=name, analyst=analyst, notes=notes)
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "INSERT INTO cases (id, name, analyst, created_at, updated_at, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case.id, case.name, case.analyst, now, now, "open", case.notes),
        )
        self.conn.commit()
        case.created_at = now
        case.updated_at = now
        return case

    def get_case(self, case_id: str) -> Case | None:
        row = self.conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            return None
        return Case(
            id=row["id"],
            name=row["name"],
            analyst=row["analyst"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=row["status"],
            notes=row["notes"],
        )

    def list_cases(self, status: str | None = None) -> list[Case]:
        if status:
            rows = self.conn.execute("SELECT * FROM cases WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        return [Case(
            id=r["id"], name=r["name"], analyst=r["analyst"],
            created_at=r["created_at"], updated_at=r["updated_at"],
            status=r["status"], notes=r["notes"],
        ) for r in rows]

    def close_case(self, case_id: str) -> bool:
        now = datetime.now(UTC).isoformat()
        cur = self.conn.execute("UPDATE cases SET status = 'closed', updated_at = ? WHERE id = ?", (now, case_id))
        self.conn.commit()
        return cur.rowcount > 0

    # Allowed columns for update_case — prevents SQL injection via kwargs keys
    _UPDATABLE_COLUMNS: ClassVar[set[str]] = {"name", "analyst", "status", "notes"}

    def update_case(self, case_id: str, **kwargs) -> bool:
        if not kwargs:
            return False
        # Whitelist column names to prevent SQL injection
        safe_kwargs = {k: v for k, v in kwargs.items() if k in self._UPDATABLE_COLUMNS}
        if not safe_kwargs:
            return False
        safe_kwargs["updated_at"] = datetime.now(UTC).isoformat()
        sets = ", ".join(f"{k} = ?" for k in safe_kwargs)
        vals = [*list(safe_kwargs.values()), case_id]
        cur = self.conn.execute(f"UPDATE cases SET {sets} WHERE id = ?", vals)
        self.conn.commit()
        return cur.rowcount > 0

    def delete_case(self, case_id: str) -> bool:
        self.conn.execute("DELETE FROM artifacts WHERE case_id = ?", (case_id,))
        self.conn.execute("DELETE FROM timeline WHERE case_id = ?", (case_id,))
        self.conn.execute("DELETE FROM hunt_results WHERE case_id = ?", (case_id,))
        self.conn.execute("DELETE FROM evidence WHERE case_id = ?", (case_id,))
        cur = self.conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        self.conn.commit()
        return cur.rowcount > 0

    def add_evidence(self, case_id: str, evidence_id: str, etype: str, path: str,
                     filename: str, size_bytes: int, sha256: str, md5: str, fmt: str) -> bool:
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "INSERT INTO evidence (id, case_id, type, path, filename, size_bytes, sha256, md5, format, ingested_at, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (evidence_id, case_id, etype, path, filename, size_bytes, sha256, md5, fmt, now),
        )
        self.conn.commit()
        return True

    def list_evidence(self, case_id: str) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def add_artifact(self, case_id: str, evidence_id: str | None, source: str,
                     category: str, timestamp: str, description: str,
                     severity: str = "info", data: str = "{}", artifact_id: str = "") -> str:
        aid = artifact_id or str(uuid.uuid4())[:12]
        severity = self._normalize_severity(severity, "info")
        self.conn.execute(
            "INSERT INTO artifacts (id, case_id, evidence_id, source, category, timestamp, description, severity, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (aid, case_id, evidence_id or None, source, category, timestamp, description, severity, data),
        )
        self.conn.commit()
        return aid

    def list_artifacts(self, case_id: str, source: str | None = None) -> list[dict]:
        if source:
            rows = self.conn.execute("SELECT * FROM artifacts WHERE case_id = ? AND source = ?", (case_id, source)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM artifacts WHERE case_id = ?", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def add_timeline_entry(self, case_id: str, source: str, timestamp: str,
                           description: str, severity: str = "info",
                           evidence_id: str | None = None, artifact_id: str = "") -> int:
        severity = self._normalize_severity(severity, "info")
        cur = self.conn.execute(
            "INSERT INTO timeline (case_id, evidence_id, source, timestamp, description, severity, artifact_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, evidence_id or None, source, timestamp, description, severity, artifact_id or None),
        )
        self.conn.commit()
        # lastrowid is None only if no INSERT succeeded or the driver doesn't
        # support it; sqlite3 always returns an int for a successful INSERT.
        lastrowid = cur.lastrowid
        return lastrowid if lastrowid is not None else -1

    def get_timeline(self, case_id: str, from_ts: str = "", to_ts: str = "") -> list[dict]:
        query = "SELECT * FROM timeline WHERE case_id = ?"
        params: list = [case_id]
        if from_ts:
            query += " AND timestamp >= ?"
            params.append(from_ts)
        if to_ts:
            query += " AND timestamp <= ?"
            params.append(to_ts)
        query += " ORDER BY timestamp ASC"
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def add_hunt_result(self, case_id: str, result_id: str, rule_name: str,
                        rule_type: str, severity: str = "medium",
                        evidence_id: str | None = None, match_offset: int = 0,
                        match_data: str = "") -> None:
        severity = self._normalize_severity(severity, "medium")
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "INSERT INTO hunt_results (id, case_id, rule_name, rule_type, evidence_id, match_offset, match_data, severity, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (result_id, case_id, rule_name, rule_type, evidence_id, match_offset, match_data, severity, now),
        )
        self.conn.commit()

    def get_hunt_results(self, case_id: str) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM hunt_results WHERE case_id = ? ORDER BY detected_at DESC", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self.conn.close()
