# 🔍 DEADDROP — Digital Forensics Toolkit

**Unified DFIR toolkit with AI-assisted triage, modern web dashboard, and automated reporting.**

[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![Tests: 128 passing](https://img.shields.io/badge/Tests-128%20passing-brightgreen.svg)](tests/)
[![Lint: 0 errors](https://img.shields.io/badge/Ruff-0%20errors-green.svg)](https://docs.astral.sh/ruff/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🎯 What is DEADDROP?

DEADDROP is a CLI-first digital forensics toolkit that unifies disk forensics, memory forensics, timeline analysis, artifact hunting, and AI-assisted triage into a single workflow. It fills the gap between monolithic GUIs (Autopsy) and fragmented CLI tools (TSK, Volatility) — fast enough for field use, visual enough for reporting, modular enough to extend.

**Killer feature:** AI-assisted triage with anomaly detection and LLM case summaries — no other open-source DFIR tool does this well.

---

## ✨ Features

- 🗄️ **Evidence Management** — Chain of custody with SHA-256/MD5 verification at every step
- 💾 **Disk Forensics** — Filesystem parsing, streaming file carving, registry analysis, prefetch, event logs, MFT parsing
- 🧠 **Memory Forensics** — Volatility3 wrapper for process analysis, network connections, malware detection
- ⏱️ **Super-Timeline** — Merge disk + memory + log artifacts into unified timeline (CSV/JSON/body file export)
- 🎯 **Artifact Hunting** — YARA scanning, IOC matching, pre-built hunt packs (persistence, lateral movement, exfiltration)
- 🤖 **AI Triage** — Statistical anomaly detection (temporal bursts, severity outliers, attack patterns) + LLM case summaries (Ollama)
- 📄 **Reporting** — Professional HTML/PDF reports with embedded evidence, chain of custody, and timeline visualization
- 🔌 **Plugin System** — Extend without touching core (Python entry points)
- 📊 **Web Dashboard** — React 19 + D3 interactive timeline visualization

---

## 🚀 Quick Start

### Install

```bash
# Clone
git clone https://github.com/aiagentmackenzie-lang/DEADDROP.git
cd DEADDROP

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with pip
pip install -e .

# Or with all extras
pip install -e ".[disk,memory,pdf,dev]"
```

### Create a Case

```bash
# Create a forensic case
deaddrop case create --name "Incident-2026-001" --analyst "Raphael"

# Ingest evidence
deaddrop ingest disk --image suspect.dd --case <case-id>
deaddrop ingest memory --dump memory.raw --case <case-id>
```

### Analyze

```bash
# Filesystem analysis
deaddrop analyze filesystem --case <case-id>

# Memory analysis (requires Volatility3)
deaddrop analyze memory --case <case-id> --plugin windows.pslist

# Event log analysis
deaddrop analyze events --case <case-id>

# Registry analysis
deaddrop analyze registry --case <case-id>

# Prefetch analysis
deaddrop analyze prefetch --case <case-id>
```

### Hunt

```bash
# YARA scan with custom rules
deaddrop hunt run --case <case-id> --yara /path/to/rules/

# Pre-built hunt packs (persistence, lateral_movement, exfiltration)
deaddrop hunt run --case <case-id> --pack persistence

# IOC matching
deaddrop hunt run --case <case-id> --ioc iocs.json
```

### AI Triage

```bash
# Run anomaly scoring
deaddrop triage run --case <case-id>

# LLM case summary (requires Ollama)
deaddrop triage summary --case <case-id>
```

### Timeline

```bash
# Generate super-timeline
deaddrop timeline generate --case <case-id>

# Export
deaddrop timeline export --case <case-id> --format csv
deaddrop timeline export --case <case-id> --format json
deaddrop timeline export --case <case-id> --format body

# Filter by time range or source
deaddrop timeline filter --case <case-id> --from 2026-04-01 --to 2026-04-15
deaddrop timeline filter --case <case-id> --source events
```

### Report

```bash
# HTML report
deaddrop report generate --case <case-id> --format html

# PDF report (requires weasyprint + system libs: pango, gdk-pixbuf)
deaddrop report generate --case <case-id> --format pdf
```

### Dashboard

```bash
# Launch web UI
deaddrop dashboard --port 8080
```

### Docker

```bash
# Full stack with one command
docker-compose up
```

Dashboard: http://localhost:3000  
API: http://localhost:8080

Or start the API server directly (requires Node.js):

```bash
cd server && npm install && npm run dev
```

Then in a separate terminal for the dashboard:

```bash
cd dashboard && npm install && npm run dev
```

---

## 🧪 Testing

```bash
# Run full test suite (128 tests)
pytest tests/ -v

# Lint check (0 errors)
ruff check src/ tests/
```

Test coverage spans: case management, evidence ingestion, file carving, MFT parsing, anomaly detection, triage scoring, timeline engine, report generation, config, and CLI commands.

---

## 🏗️ Architecture

```
CLI (Click) → Core Engine (Python) → API Server (Fastify/TS) → Dashboard (React + D3)
                  ↓
    ┌─────────────┼──────────────┐
    │             │              │
  Disk          Memory        Timeline
  Forensics     Forensics     Engine
    │             │              │
    └─────────────┼──────────────┘
                  ↓
         Artifact Hunter (YARA + IOC)
                  ↓
         AI Triage (Anomaly + LLM)
                  ↓
         Report Generator (HTML + PDF)
```

---

## 📂 Project Structure

```
DEADDROP/
├── src/deaddrop/         # Python engine (~3,650 LOC)
│   ├── cli/              # Click CLI commands
│   ├── core/             # Case management, evidence, config
│   ├── disk/             # Disk forensics (filesystem, carving, registry, prefetch, events, MFT)
│   ├── memory/           # Memory forensics (Volatility3 wrapper)
│   ├── timeline/         # Timeline engine + export
│   ├── hunt/             # YARA scanner + IOC matcher + hunt packs
│   ├── triage/           # AI anomaly detection + LLM summaries
│   ├── report/           # HTML/PDF report generation
│   └── plugins/          # Plugin system + built-in plugins
├── server/               # Fastify API server (TypeScript)
├── dashboard/            # React 19 + D3 dashboard
├── rules/                # YARA rules (malware, persistence, suspicious)
├── tests/                # pytest test suite (128 tests)
└── docs/                 # Documentation
```

---

## 🔬 Supported Evidence Formats

| Type | Formats |
|------|---------|
| **Disk** | RAW/DD, E01, VMDK, QCOW2, ISO, IMG |
| **Memory** | RAW, VMEM, Windows Crash Dump (.dmp), ELF64 |

Format detection uses both file extension and magic bytes (EWF, KDMV, QFI\xfb, ELF, MDMP, PAGE). Windows Minidump (MDMP magic) is also detected within .dmp files.

---

## 📋 Security Event Coverage

28 Windows security event IDs classified for triage, including: Logon/Logoff (4624/4625/4634), Credential Access (4648/4768/4769), Process Creation (4688), Service Installation (4697/7045), Scheduled Tasks (4698/4702), Audit Clearing (1102), and more.

---

## 🔒 Security Notes

- **File carving** uses streaming reads (4MB chunks) — never loads entire disk images into RAM
- **No hallucinated artifacts** — parsers return empty results when no real data is found; reference data is used for classification only
- **Chain of custody** — SHA-256 + MD5 hashes computed at ingestion and re-verified on demand
- **Plugin sandboxing** — plugins run in isolated entry points, cannot modify core engine

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Write tests (pytest + ruff)
4. Submit a PR

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🏷️ Tags

`digital-forensics` `dfir` `incident-response` `yara` `volatility` `timeline` `memory-forensics` `disk-forensics` `ai-triage` `cybersecurity`

---

Built by [Agent Mackenzie](https://github.com/aiagentmackenzie-lang) for [Raphael's Security Portfolio](https://github.com/aiagentmackenzie-lang)