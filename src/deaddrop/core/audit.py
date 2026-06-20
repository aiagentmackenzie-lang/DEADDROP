"""Tamper-evident append-only audit log for case mutations.

Chain-of-custody requires that every mutation of a case (create/update/close/
delete/ingest/artifact/timeline/hunt) be recorded in a log that cannot be
silently altered. This module writes an append-only JSONL log where each entry
includes a SHA-256 of the previous entry's canonical bytes — so any tampering
or deletion breaks the hash chain (detectable on verification).

The log file lives outside the SQLite case DB (default: ~/.deaddrop/audit.log,
overridable via DEADDROP_AUDIT_LOG) so a compromised DB write path can't also
rewrite the audit trail.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_LOCK = threading.Lock()
_HEAD_HASH = "0" * 64  # genesis hash for the first entry


def _audit_log_path() -> Path:
    env = os.environ.get("DEADDROP_AUDIT_LOG")
    if env:
        return Path(env)
    home = os.environ.get("DEADDROP_HOME") or str(Path.home())
    return Path(home) / ".deaddrop" / "audit.log"


def _last_hash(path: Path) -> str:
    """Return the hash of the last line in the audit log (or genesis)."""
    if not path.exists():
        return _HEAD_HASH
    last_line = b""
    try:
        with open(path, "rb") as f:
            for line in f:
                if line.strip():
                    last_line = line.rstrip(b"\n")
    except OSError:
        return _HEAD_HASH
    if not last_line:
        return _HEAD_HASH
    try:
        h = json.loads(last_line.decode("utf-8")).get("hash", _HEAD_HASH)
        return str(h)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _HEAD_HASH


def audit(action: str, case_id: str | None = None, actor: str = "",
           **details: Any) -> None:
    """Append a tamper-evident audit record.

    Each record: {ts, action, case_id, actor, details, prev_hash, hash} where
    `hash` = sha256(prev_hash + canonical(record_without_hash)). Appending is
    serialized across threads. Failures to write are LOGGED but never raise —
    audit logging must not crash a forensic operation mid-flight (the operation
    itself is the thing being audited). Callers that need fail-closed auditing
    should check the log explicitly.
    """
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "action": action,
        "case_id": case_id,
        "actor": actor,
        "details": details,
    }
    try:
        path = _audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK:
            prev = _last_hash(path)
            record["prev_hash"] = prev
            canon = json.dumps({k: v for k, v in record.items() if k != "hash"},
                               sort_keys=True, default=str).encode("utf-8")
            record["hash"] = hashlib.sha256(prev.encode("utf-8") + canon).hexdigest()
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
    except OSError as e:
        log.warning("audit log write failed (%s: %s) — record: %s",
                    type(e).__name__, e, action)


def verify_audit_log(path: Path | None = None) -> dict:
    """Verify the hash chain of the audit log. Returns {valid, entries, broken_at}."""
    p = path or _audit_log_path()
    if not p.exists():
        return {"valid": True, "entries": 0, "broken_at": None}
    prev = _HEAD_HASH
    count = 0
    with open(p, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            count += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return {"valid": False, "entries": count, "broken_at": i}
            expected_prev = rec.get("prev_hash")
            if expected_prev != prev:
                return {"valid": False, "entries": count, "broken_at": i}
            canon = json.dumps(
                {k: v for k, v in rec.items() if k != "hash"},
                sort_keys=True, default=str,
            ).encode("utf-8")
            expected_hash = hashlib.sha256(
                prev.encode("utf-8") + canon
            ).hexdigest()
            if rec.get("hash") != expected_hash:
                return {"valid": False, "entries": count, "broken_at": i}
            prev = rec["hash"]
    return {"valid": True, "entries": count, "broken_at": None}
