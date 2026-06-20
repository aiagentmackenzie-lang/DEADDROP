# 🔍 DEADDROP — Digital Forensics Toolkit

**Unified DFIR toolkit with AI-assisted triage, in-process REST/WebSocket API, and automated court-grade reporting.**

[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![Tests: 196 passing](https://img.shields.io/badge/Tests-196%20passing-brightgreen.svg)](tests/)
[![Lint: ruff clean](https://img.shields.io/badge/Ruff-clean-green.svg)](https://docs.astral.sh/ruff/)
[![Types: mypy clean](https://img.shields.io/badge/mypy-clean-green.svg)](https://mypy-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🎯 What is DEADDROP?

DEADDROP is a CLI-first digital forensics toolkit that unifies disk forensics, memory forensics, timeline analysis, artifact hunting, and AI-assisted triage into a single workflow. It fills the gap between monolithic GUIs (Autopsy) and fragmented CLI tools (TSK, Volatility) — fast enough for field use, visual enough for reporting, modular enough to extend.

**Differentiator:** AI-assisted triage with statistical anomaly detection + LLM case summaries, a tamper-evident audit log, and chain-of-custody integrity gates on report generation — no other open-source DFIR CLI does this.

---

## ✨ Features (honest status)

| Area | Feature | Status |
|---|---|---|
| **Evidence** | Chain of custody (SHA-256 + MD5 at ingestion, re-verify on demand, directory manifests) | ✅ Verified |
| **Evidence** | Disk/memory format detection (magic bytes + extension) | ✅ Verified |
| **Disk** | Filesystem parsing via pytsk3 (with raw fallback) | ✅ Requires `pip install -e ".[disk]"` |
| **Disk** | Streaming file carving (stateful, cross-chunk) | ✅ Verified |
| **Disk** | MFT parsing (NTFS entry/attribute/timestamps) | ⚠️ Spec-conformant; validate against your target's MFT variant |
| **Disk** | EVTX parsing (python-evtx, security-event classification) | ✅ Requires `pip install -e ".[evtx]"` |
| **Disk** | Registry hive parsing (python-registry, forensic-key walk) | ✅ Requires `pip install -e ".[registry]"` |
| **Disk** | Prefetch (.pf) SCCA parsing (v23/v26/v30/v31) | ⚠️ run_count offset is build-stable; validate against your Windows build |
| **Memory** | Volatility3 wrapper (plugin whitelist, command-injection-safe) | ✅ Requires `pip install -e ".[memory]"` + Volatility3 installed |
| **Timeline** | Super-timeline (CSV / JSON / TSK body file export, filter) | ✅ Verified |
| **Hunt** | YARA scanning (chunked for multi-GB images, deduped hits) | ✅ Verified |
| **Hunt** | IOC matching (regex + JSON/STIX ingest, RFC 1918-aware severity) | ✅ Verified |
| **Hunt** | Pre-built packs (persistence, lateral_movement, exfiltration) | ✅ Verified |
| **Triage** | Statistical anomaly detection (temporal bursts, severity, source, attack patterns) | ✅ Verified |
| **Triage** | LLM case summaries (Ollama, rule-based fallback + logged failures) | ⚠️ Requires a running Ollama |
| **Report** | HTML reports (XSS-escaped) | ✅ Verified |
| **Report** | PDF reports (WeasyPrint) | ✅ Requires `pip install -e ".[pdf]"` + system libs |
| **Report** | Chain-of-custody integrity gate (refuses tampered/missing evidence) | ✅ Verified |
| **Plugins** | Plugin manager (load, list, run, manifest-driven) | ✅ Verified |
| **Plugins** | Pipeline hooks (`run_hooks`) | ❌ Defined but NOT wired into CLI commands — manual `plugin run` only |
| **API** | In-process FastAPI REST API (Pydantic validation, bearer auth, CORS allowlist) | ✅ Verified |
| **API** | WebSocket event bus (case lifecycle events, heartbeats) | ✅ Verified |
| **API** | Rate limiting on expensive endpoints | ✅ Verified (per-process) |
| **Audit** | Tamper-evident append-only audit log (hash-chained) | ✅ Verified |
| **Dashboard** | React 19 + D3 dashboard (built static, served by the API) | ⚠️ Build with `cd dashboard && npm run build`; API-only mode otherwise |

**Not implemented (deliberately honest):**
- Plugin sandboxing — plugins run in-process via `importlib`; the README previously claimed isolation that didn't exist. Removed the claim. Treat plugins as trusted code.
- Pipeline hooks firing automatically — `run_hooks` exists but no CLI command invokes it. Use `deaddrop plugin run <name>`.

---

## 🚀 Quick Start

### Install

```bash
git clone https://github.com/aiagentmackenzie-lang/DEADDROP.git
cd DEADDROP
python -m venv .venv && source .venv/bin/activate
pip install -e ".[disk,memory,pdf,evtx,registry,dev]"
```

### Create a Case

```bash
deaddrop case create --name "Incident-2026-001" --analyst "Raphael"
# Ingest evidence (files or directories of extracted artifacts)
deaddrop ingest disk   --image ./evidence/suspect.dd   --case <case-id>
deaddrop ingest memory --dump  ./evidence/memory.raw   --case <case-id>
```

### Analyze

```bash
deaddrop analyze filesystem --case <case-id>
deaddrop analyze events     --case <case-id>   # parses EVTX, classifies 28 security event IDs
deaddrop analyze registry   --case <case-id>   # walks Run keys, services, USB, persistence
deaddrop analyze prefetch   --case <case-id>   # parses SCCA .pf files
deaddrop analyze memory     --case <case-id> --plugin windows.pslist
```

### Hunt

```bash
deaddrop hunt run --case <case-id> --yara ./rules/malware/      # scan with YARA rules
deaddrop hunt run --case <case-id> --pack persistence           # pre-built pack
deaddrop hunt run --case <case-id> --ioc iocs.json               # IOC matching
```

### AI Triage

```bash
deaddrop triage run     --case <case-id>   # anomaly scoring
deaddrop triage summary --case <case-id>   # LLM summary (Ollama) or rule-based fallback
```

### Timeline

```bash
deaddrop timeline generate --case <case-id>
deaddrop timeline export   --case <case-id> --format csv   # csv | json | body
deaddrop timeline filter   --case <case-id> --from 2026-04-01 --to 2026-04-15
```

### Report

```bash
deaddrop report generate --case <case-id> --format html
deaddrop report generate --case <case-id> --format pdf    # refuses if any evidence fails integrity
```

### API + Dashboard

```bash
# Set a token before binding anything beyond localhost
export DEADDROP_API_TOKEN="$(openssl rand -hex 32)"
deaddrop dashboard --port 8080 --host 127.0.0.1
# → API at http://127.0.0.1:8080/api/health
# → Dashboard at http://127.0.0.1:8080/  (if built: cd dashboard && npm run build)
# → WebSocket at ws://127.0.0.1:8080/ws
```

The dashboard is built separately and served by the API as static files:

```bash
cd dashboard && npm install && npm run build   # → dashboard/dist, served at /
```

### Docker

```bash
export DEADDROP_API_TOKEN="change-me"
docker compose up --build
# → http://localhost:8080  (API + dashboard in one container)
```

---

## 🧪 Testing

```bash
pytest tests/ -v          # 196 tests
ruff check src/ tests/     # clean
mypy src                   # clean (47 files)
```

Coverage spans: case CRUD, evidence ingestion + integrity, carving (incl.
cross-chunk), MFT parsing, EVTX/registry/prefetch parsing, anomaly detection,
triage, timeline engine/export, report generation + integrity gate, plugin
manager, audit log + tamper detection, FastAPI API (auth, validation,
WebSocket, rate limit).

---

## 🏗️ Architecture

```
CLI (Click) ─→ Core Engine (Python) ─→ FastAPI API (in-process) ─→ React + D3 Dashboard
                    │
    ┌───────────────┼────────────────┐
    │               │                │
  Disk          Memory           Timeline
  Forensics     Forensics        Engine
    │               │                │
    └───────────────┼────────────────┘
                    │
            Artifact Hunter (YARA + IOC)
                    │
            AI Triage (Anomaly + LLM)
                    │
            Report Generator (HTML + PDF, integrity-gated)
                    │
            Audit Log (tamper-evident, append-only)
```

- **Core engine** — SQLite (WAL, FK-enforced, `ON DELETE CASCADE`) for cases/evidence/artifacts/timeline/hunt_results.
- **API** — in-process Fastify→FastAPI (the previous TS subprocess bridge that JSON.parsed Rich console output is gone). Per-request `CaseManager`, Pydantic validation, bearer auth, CORS allowlist, rate limiting, WebSocket event bus.
- **Dashboard** — React 19 + D3, built by Vite, served as static files by the API.
- **Audit log** — append-only JSONL with a SHA-256 hash chain, stored outside the DB.

---

## 📂 Project Structure

```
DEADDROP/
├── src/deaddrop/         # Python engine
│   ├── api/               # FastAPI app, routes, deps, models, event bus
│   ├── cli/               # Click CLI
│   ├── core/              # case, evidence, config, audit
│   ├── disk/              # filesystem, carving, registry, prefetch, events, mft
│   ├── memory/            # Volatility3 wrapper
│   ├── timeline/          # engine + export (csv/json/body)
│   ├── hunt/              # yara_scanner + ioc_matcher + packs + rules/
│   ├── triage/            # anomaly + llm + scorer
│   ├── report/            # HTML/PDF generator (integrity-gated)
│   └── plugins/           # manager + hooks + builtins
├── dashboard/            # React 19 + D3 (build → dist, served by API)
├── rules/                # (moved into src/deaddrop/rules — packaged)
├── tests/                # pytest suite (196 tests)
├── docs/                 # architecture / user-guide / plugin-development
└── pyproject.toml
```

---

## 🔬 Supported Evidence Formats

| Type | Formats |
|---|---|
| **Disk** | RAW/DD, E01, VMDK, QCOW2, ISO, IMG |
| **Memory** | RAW, VMEM, Windows Crash Dump (incl. Minidump MDMP), ELF64 |

Format detection uses both file extension and magic bytes (EWF, KDMV, QFI\xfb, ELF, MDMP, PAGE).

---

## 🔒 Security

- **Auth** — bearer-token API auth (`DEADDROP_API_TOKEN`); default-deny when set, disabled+warned in dev. Server binds `127.0.0.1` by default — never bind `0.0.0.0` without a token.
- **CORS** — allowlist (localhost defaults); configurable via `DEADDROP_CORS_ORIGINS`.
- **Input validation** — every API body validated with Pydantic (`as any` is gone; argument injection closed).
- **Rate limiting** — expensive endpoints (ingest/hunt/analyze/report) are rate-limited per client IP.
- **Chain of custody** — SHA-256 + MD5 at ingestion; re-verify on demand; report generation **refuses** to render against tampered or missing evidence.
- **Audit log** — every case mutation recorded in a tamper-evident, hash-chained, append-only log outside the DB.
- **File carving** — streaming reads (4MB chunks); stateful across chunk boundaries; memory bounded by per-signature `max_size`.
- **No fake artifacts** — parsers return empty results when no real data is found; reference data (SECURITY_EVENTS, FORENSIC_KEYS) is for classification only.
- **Plugins are trusted** — they run in-process (no sandbox). Do not load untrusted plugins.

---

## ⚙️ Configuration

All settings are optional env vars (see `.env.example`):

| Var | Default | Purpose |
|---|---|---|
| `DEADDROP_HOME` | `~/.deaddrop` | cases.db, plugins, audit.log live here |
| `DEADDROP_API_TOKEN` | unset | bearer token; set for any non-loopback deploy |
| `DEADDROP_HOST` / `DEADDROP_PORT` | `127.0.0.1` / `8080` | API bind |
| `DEADDROP_CORS_ORIGINS` | localhost set | comma-separated allowed origins |
| `DEADDROP_WS_TIMEOUT` | `30` | WebSocket idle heartbeat (s) |
| `DEADDROP_AUDIT_LOG` | `<HOME>/.deaddrop/audit.log` | audit log path |
| `DEADDROP_RATE_LIMIT` | `20/60` | `limit/window_seconds` per client IP |
| `OLLAMA_URL` / `OLLAMA_MODEL` | `http://localhost:11434` / `llama3` | AI triage |

---

## 🤝 Contributing

1. Fork → feature branch
2. Write tests (`pytest` + `ruff` + `mypy` must stay green)
3. Verify any new parser against real fixtures, not tautologies
4. Submit a PR

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🗂️ Changes

See [CHANGELOG.md](CHANGELOG.md).

---

`digital-forensics` `dfir` `incident-response` `yara` `volatility` `timeline` `memory-forensics` `disk-forensics` `ai-triage` `chain-of-custody`

Built by [Agent Mackenzie](https://github.com/aiagentmackenzie-lang) for Raphael's Security Portfolio.