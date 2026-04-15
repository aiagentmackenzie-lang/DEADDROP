# DEADDROP Architecture

## Overview

DEADDROP follows a layered architecture:

1. **CLI Layer** (Click) — User-facing commands
2. **Core Engine** (Python) — Business logic, data persistence (SQLite)
3. **API Server** (Fastify + TypeScript) — REST + WebSocket bridge
4. **Dashboard** (React + D3) — Interactive visualization

## Data Flow

```
Evidence → Ingest → Hash Verify → Store in SQLite
                                    ↓
                              Analyze (Disk/Memory)
                                    ↓
                              Timeline Engine
                                    ↓
                              Hunt (YARA/IOC)
                                    ↓
                              AI Triage
                                    ↓
                              Report Generation
```

## Database Schema

- `cases` — Case metadata
- `evidence` — Ingested evidence with hashes
- `artifacts` — Analysis findings
- `timeline` — Unified timeline entries
- `hunt_results` — YARA/IOC match results

All tables use foreign keys to `cases.id` for cascading deletes.

## Plugin System

Plugins are Python packages with a `plugin.json` manifest. They register hooks at pipeline stages:

- `pre_ingest` / `post_ingest`
- `pre_analyze` / `post_analyze`
- `pre_hunt` / `post_hunt`
- `pre_report` / `post_report`
- `custom`

## API Server

The Fastify server bridges the Python CLI to the React dashboard via subprocess calls. WebSocket provides real-time event updates.