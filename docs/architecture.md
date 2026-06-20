# DEADDROP Architecture

## Overview

DEADDROP is a layered, in-process DFIR toolkit:

1. **CLI Layer** (Click) — user-facing commands (`deaddrop <group> <cmd>`).
2. **Core Engine** (Python) — business logic, SQLite persistence, audit log.
3. **API Server** (FastAPI, in-process) — REST + WebSocket; calls the engine directly (no subprocess).
4. **Dashboard** (React 19 + D3) — built static bundle served by the API at `/`.

> The previous architecture used a Node (Fastify) server that shelled out to
> the `deaddrop` CLI and `JSON.parse`d Rich-formatted console output — which
> returned `{raw: "<ansi>"}` for every call and was unreachable across Docker
> containers. It was replaced in v1.2.0 with the in-process FastAPI app.

## Data Flow

```
Evidence → Ingest (hash verify) → Store in SQLite (+ audit record)
                                    ↓
                              Analyze (Disk/Memory/Events/Registry/Prefetch)
                                    ↓
                              Timeline Engine (super-timeline)
                                    ↓
                              Hunt (YARA/IOC)
                                    ↓
                              AI Triage (Anomaly + LLM)
                                    ↓
                              Report Generation (integrity-gated, HTML/PDF)
                                    ↓
                              Audit Log (hash-chained, append-only)
```

Every mutation emits an `events.bus.publish_sync(...)` so connected WebSocket
clients get a live event, AND appends a tamper-evident record to the audit log.

## Database Schema

- `cases` — case metadata (PK `id`).
- `evidence` — ingested evidence with SHA-256 + MD5; `FK case_id … ON DELETE CASCADE`.
- `artifacts` — analysis findings; `FK case_id … ON DELETE CASCADE`,
  `FK evidence_id … ON DELETE SET NULL` (orphan-preserve).
- `timeline` — unified timeline entries; `FK case_id … ON DELETE CASCADE`.
- `hunt_results` — YARA/IOC match results; `FK case_id … ON DELETE CASCADE`.

`PRAGMA journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. `delete_case`
is transactional (ordered child deletes + case delete in one transaction).

## API Server

FastAPI app factory (`create_app()` in `src/deaddrop/api/app.py`):
- Per-request `CaseManager` via a SYNC generator dependency (same worker thread
  as the route handler — sqlite3 connections are thread-bound).
- Pydantic models validate every body (`src/deaddrop/api/models.py`).
- Bearer-token auth (`DEADDROP_API_TOKEN`); default-deny when set.
- CORS allowlist (`DEADDROP_CORS_ORIGINS`); localhost defaults.
- Rate limiting on expensive endpoints (`DEADDROP_RATE_LIMIT`).
- WebSocket `/ws` streams case lifecycle events from `EventBus` (with a
  heartbeat every `DEADDROP_WS_TIMEOUT` seconds).
- Serves the built dashboard at `/` via `StaticFiles` when `dashboard/dist`
  exists (API-only mode otherwise).
- Lifespan binds the running event loop to the EventBus so sync route handlers
  (which run in a worker thread) can publish via `call_soon_threadsafe`.

## Audit Log

`src/deaddrop/core/audit.py` — append-only JSONL at
`<DEADDROP_HOME>/.deaddrop/audit.log`. Each record:
`{ts, action, case_id, actor, details, prev_hash, hash}` where
`hash = sha256(prev_hash + canonical(record_without_hash))`. `verify_audit_log()`
walks the chain and flags any edit/deletion. The log lives outside the SQLite
DB so a compromised DB write path cannot rewrite the trail.

## Plugin System

Plugins are directories with a `plugin.json` manifest + a `main.py` exposing
`run(case_id, **kwargs)`. The manager loads them via `importlib.util` (note:
`import importlib` alone does NOT expose `importlib.util` — this was a real
crash bug in v1.0, fixed in v1.2.0). **Plugins run in-process — there is no
sandbox. Treat plugins as trusted code.**

Hook points (`pre_ingest`/`post_ingest`/…/`custom`) are defined in
`plugins/hooks.py` and `run_hooks()` exists, but **no CLI command invokes them
automatically**. Run plugins explicitly with `deaddrop plugin run <name>`.