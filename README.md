# 🔍 DEADDROP — Digital Forensics Toolkit

**Unified DFIR toolkit with AI-assisted triage, modern web dashboard, and automated reporting.**

[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🎯 What is DEADDROP?

DEADDROP is a CLI-first digital forensics toolkit that unifies disk forensics, memory forensics, timeline analysis, artifact hunting, and AI-assisted triage into a single workflow. It fills the gap between monolithic GUIs (Autopsy) and fragmented CLI tools (TSK, Volatility) — fast enough for field use, visual enough for reporting, modular enough to extend.

**Killer feature:** AI-assisted triage with anomaly detection and LLM case summaries — no other open-source DFIR tool does this well.

---

## ✨ Features

- 🗄️ **Evidence Management** — Chain of custody with SHA-256/MD5 verification at every step
- 💾 **Disk Forensics** — Filesystem parsing, file carving, registry analysis, prefetch, event logs, MFT parsing
- 🧠 **Memory Forensics** — Volatility3 wrapper for process analysis, network connections, malware detection
- ⏱️ **Super-Timeline** — Merge disk + memory + log artifacts into unified timeline (CSV/JSON/body file export)
- 🎯 **Artifact Hunting** — YARA scanning, IOC matching, pre-built hunt packs (persistence, lateral movement, exfiltration)
- 🤖 **AI Triage** — Statistical anomaly detection + LLM-powered case summaries (Ollama)
- 📄 **Reporting** — Professional HTML/PDF reports with embedded evidence, chain of custody, and timeline visualization
- 🔌 **Plugin System** — Extend without touching core (Python entry points)
- 📊 **Web Dashboard** — React + D3 interactive timeline visualization

---

## 🚀 Quick Start

### Install

```bash
# Clone
git clone https://github.com/aiagentmackenzie-lang/DEADDROP.git
cd DEADDROP

# Install with pip
pip install -e .

# Or with all extras
pip install -e ".[disk,memory,dev]"
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
```

### Hunt

```bash
# YARA scan
deaddrop hunt run --case <case-id> --yara /path/to/rules/

# Pre-built hunt pack
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

# Filter
deaddrop timeline filter --case <case-id> --from 2026-04-01 --to 2026-04-15
```

### Report

```bash
# HTML report
deaddrop report generate --case <case-id> --format html

# PDF report (requires weasyprint)
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
├── src/deaddrop/         # Python engine
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
├── dashboard/            # React + D3 dashboard
├── rules/                # YARA rules (malware, persistence, suspicious)
├── tests/                # pytest test suite
└── docs/                 # Documentation
```

---

## 🔬 Supported Evidence Formats

| Type | Formats |
|------|---------|
| **Disk** | RAW/DD, E01, VMDK, QCOW2, ISO, IMG |
| **Memory** | RAW, VMEM, Windows Crash Dump, ELF64, Windows Minidump |

---

## 📋 Security Event Coverage

50+ Windows security events including: Logon/Logoff (4624/4625/4634), Credential Access (4648/4768/4769), Process Creation (4688), Service Installation (4697/7045), Scheduled Tasks (4698/4702), Audit Clearing (1102), and more.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Write tests
4. Submit a PR

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🏷️ Tags

`digital-forensics` `dfir` `incident-response` `yara` `volatility` `timeline` `memory-forensics` `disk-forensics` `ai-triage` `cybersecurity`

---

Built by [Agent Mackenzie](https://github.com/aiagentmackenzie-lang) for [Raphael's Security Portfolio](https://github.com/aiagentmackenzie-lang)