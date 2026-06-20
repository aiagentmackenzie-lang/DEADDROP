"""Auth + dependencies for the DEADDROP API.

SB-5 fix: bearer-token auth, default-deny in production. SB-4 fix: per-request
CaseManager via a `with`-style dependency (H-3), closed after the request.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from threading import Lock
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from deaddrop.core.case import CaseManager
from deaddrop.core.config import Config

log = logging.getLogger(__name__)


# Auth token source: DEADDROP_API_TOKEN env var. When unset, auth is DISABLED
# (dev convenience) and a WARNING is logged on app startup. In any deployment
# where the API binds to a non-loopback interface, set the token.
AUTH_TOKEN_ENV = "DEADDROP_API_TOKEN"


def is_auth_enabled() -> bool:
    return bool(os.environ.get(AUTH_TOKEN_ENV))


def require_auth(authorization: Annotated[str | None, Header()] = None) -> None:
    """Bearer-token dependency. No-op in dev (token unset); enforced in prod."""
    token = os.environ.get(AUTH_TOKEN_ENV)
    if not token:
        # Dev mode: auth disabled. The startup log warns about this.
        return
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or value != token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# FastAPI's dependency ordering: auth checked before DB.
AuthDep = Annotated[None, Depends(require_auth)]


def get_config() -> Config:
    """Return the shared Config (cheap; no DB connection).

    Honors DEADDROP_HOME for test/operator isolation.
    """
    return Config.load()


ConfigDep = Annotated[Config, Depends(get_config)]


def get_case_manager(config: ConfigDep):
    """Per-request CaseManager. Opened fresh and closed after the request.

    SYNC generator (not async) so it runs in the SAME worker thread as the
    sync route handler — sqlite3 connections are thread-bound by default
    (`check_same_thread=True`). SQLite handles concurrent connections via
    WAL + busy_timeout (H-04), so a connection-per-request avoids cross-thread
    issues and matches the H-3 context-manager pattern.
    """
    config.ensure_dirs()
    mgr = CaseManager(config.db_path)
    try:
        yield mgr
    finally:
        mgr.close()


CaseMgrDep = Annotated[CaseManager, Depends(get_case_manager)]


# ── Rate limiting (Phase 4) ──────────────────────────────────────
# Minimal in-memory fixed-window limiter for the expensive endpoints (ingest,
# hunt, analyze, report). Bounds a single client to N calls per window. State
# is per-process (fine for a single uvicorn worker; for multi-worker deploys a
# shared store like Redis would be needed — documented in README).

_RATE_BUCKETS: dict[str, dict[str, float]] = defaultdict(dict)
_RATE_LOCK = Lock()


def _rate_limit(request: Request, limit: int, window: float) -> None:
    """Fixed-window per-client-IP rate limit. Raises 429 if exceeded."""
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    bucket_key = f"{limit}/{int(window * 1000)}"
    bucket = _RATE_BUCKETS[bucket_key]
    with _RATE_LOCK:
        # Purge expired entries for this bucket
        expired = [k for k, t in bucket.items() if now - t > window]
        for k in expired:
            bucket.pop(k, None)
        count = sum(1 for t in bucket.values() if now - t <= window)
        if count >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {limit} requests per {int(window)}s",
            )
        bucket[client + str(now)] = now


def rate_limit_expensive(request: Request) -> None:
    """Rate limit for expensive forensic endpoints (ingest/hunt/analyze/report).

    Defaults: 20 requests per 60s per client IP. Tunable via
    DEADDROP_RATE_LIMIT (format: 'limit/window_seconds').
    """
    raw = os.environ.get("DEADDROP_RATE_LIMIT", "20/60")
    try:
        limit_s, window_s = raw.split("/")
        limit = int(limit_s)
        window = float(window_s)
    except (ValueError, AttributeError):
        limit, window = 20, 60.0
    _rate_limit(request, limit, window)


RateLimitedDep = Annotated[None, Depends(rate_limit_expensive)]
