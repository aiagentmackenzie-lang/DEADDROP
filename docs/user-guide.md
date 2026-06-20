# DEADDROP User Guide

## Installation

### Prerequisites
- Python 3.12+
- (Optional) Volatility3 — for memory forensics (`pip install -e ".[memory]"`)
- (Optional) Ollama — for AI triage LLM summaries
- (Optional) WeasyPrint system libs (pango, gdk-pixbuf) — for PDF reports
- (Optional) Node 20+ — to build the dashboard

### Install

```bash
git clone https://github.com/aiagentmackenzie-lang/DEADDROP.git
cd DEADDROP
python -m venv .venv && source .venv/bin/activate
pip install -e ".[disk,memory,pdf,evtx,registry,dev]"
```

## Workflow

### 1. Create a Case

```bash
deaddrop case create --name "Ransomware-Incident" --analyst "Raphael"
```

### 2. Ingest Evidence

```bash
deaddrop ingest disk   --image /evidence/suspect.E01     --case <id>
deaddrop ingest memory --dump  /evidence/memory.raw      --case <id>
# You can also ingest a directory of extracted artifacts (carved .pf/.evtx/.hive):
deaddrop ingest disk   --image /evidence/extracted/      --case <id>
```

All evidence is hashed (SHA-256 + MD5; directories use a sorted manifest hash)
and recorded with chain-of-custody metadata. Every ingestion is written to the
tamper-evident audit log.

### 3. Analyze

```bash
deaddrop analyze filesystem --case <id>
deaddrop analyze events     --case <id>   # parses EVTX → 28 security event IDs
deaddrop analyze registry   --case <id>   # walks Run keys, services, USB, persistence
deaddrop analyze prefetch   --case <id>   # parses SCCA .pf (v23/v26/v30/v31)
deaddrop analyze memory     --case <id> --plugin windows.pslist
```

### 4. Hunt

```bash
deaddrop hunt run --case <id> --yara /path/to/rules/
deaddrop hunt run --case <id> --pack persistence
deaddrop hunt run --case <id> --ioc indicators.json
```

### 5. Triage

```bash
deaddrop triage run     --case <id>   # statistical anomaly scoring
deaddrop triage summary --case <id>   # LLM summary (Ollama) or rule-based fallback
```

### 6. Report

```bash
deaddrop report generate --case <id> --format html
deaddrop report generate --case <id> --format pdf
```

Report generation **re-verifies every evidence item's hashes first** and
refuses to render if any file is missing or tampered (court-grade integrity
gate). Use `--skip-verify` only with explicit analyst sign-off.

### 7. API + Dashboard

```bash
export DEADDROP_API_TOKEN="$(openssl rand -hex 32)"   # required for non-loopback
deaddrop dashboard --port 8080 --host 127.0.0.1
```

- API: `http://127.0.0.1:8080/api/health`
- Dashboard: `http://127.0.0.1:8080/` — served from `dashboard/dist` (build it with `cd dashboard && npm install && npm run build`). API-only mode if the build is absent.
- WebSocket: `ws://127.0.0.1:8080/ws` — streams `case.*`, `evidence.*`, `analyze.*`, `hunt.*`, `triage.*`, `report.*`, `timeline.*` events.

> Note: the dashboard is **not** on port 3000 in production. In dev you can run
> `cd dashboard && npm run dev` (Vite on 3000 proxying to the API on 8080). In
> production the API serves the built dashboard at the same origin.

## Evidence Integrity

DEADDROP maintains chain of custody by:
1. Computing SHA-256 + MD5 (or a directory manifest hash) at ingestion.
2. Storing hashes in the SQLite case database.
3. Re-verifying hashes on demand (`deaddrop` API `/verify`, plugin `hash-verifier`).
4. Refusing report generation if any evidence fails verification.
5. Recording every mutation in a tamper-evident, hash-chained audit log.

## Hunt Packs

| Pack | Detection |
|------|-----------|
| `persistence` | Registry Run keys, services, scheduled tasks, WMI, shell extensions |
| `lateral_movement` | PsExec, WMI, RDP, SMB lateral movement |
| `exfiltration` | DNS tunneling, HTTP upload, cloud storage, archiving |

## AI Triage

Two approaches:
1. **Statistical anomaly detection** — temporal bursts, severity distribution,
   source dominance, attack-pattern sequences.
2. **LLM summary** — Ollama-powered NL case summary (rule-based fallback if
   Ollama is unreachable; the failure is logged, never silent).

Risk scores 0–100: ≥75 CRITICAL, ≥50 HIGH, ≥25 MEDIUM, ≥10 LOW, <10 MINIMAL.

## Docker

```bash
export DEADDROP_API_TOKEN="change-me"
docker compose up --build
# → http://localhost:8080  (single container: API + built dashboard)
```

## Audit Log Verification

```python
from deaddrop.core.audit import verify_audit_log
print(verify_audit_log())   # {valid: True, entries: N, broken_at: None}
```