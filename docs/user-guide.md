# DEADDROP User Guide

## Installation

### Prerequisites
- Python 3.12+
- (Optional) Volatility3 — for memory forensics
- (Optional) Ollama — for AI triage summaries
- (Optional) WeasyPrint — for PDF reports

### Install

```bash
git clone https://github.com/aiagentmackenzie-lang/DEADDROP.git
cd DEADDROP
pip install -e ".[disk,memory,dev]"
```

## Workflow

### 1. Create a Case

```bash
deaddrop case create --name "Ransomware-Incident" --analyst "Raphael"
```

### 2. Ingest Evidence

```bash
deaddrop ingest disk --image /evidence/suspect.E01 --case <id>
deaddrop ingest memory --dump /evidence/memory.raw --case <id>
```

All evidence is hashed (SHA-256 + MD5) and stored with chain-of-custody metadata.

### 3. Analyze

```bash
deaddrop analyze filesystem --case <id>
deaddrop analyze registry --case <id>
deaddrop analyze prefetch --case <id>
deaddrop analyze events --case <id>
deaddrop analyze memory --case <id> --plugin windows.pslist
```

### 4. Hunt

```bash
deaddrop hunt run --case <id> --yara /path/to/rules/
deaddrop hunt run --case <id> --pack persistence
deaddrop hunt run --case <id> --ioc indicators.json
```

### 5. Triage

```bash
deaddrop triage run --case <id>
deaddrop triage summary --case <id>
```

### 6. Report

```bash
deaddrop report generate --case <id> --format html
deaddrop report generate --case <id> --format pdf
```

### 7. Dashboard

```bash
deaddrop dashboard --port 8080
```

Open http://localhost:8080 for the interactive dashboard with D3 timeline visualization.

## Evidence Integrity

DEADDROP maintains chain of custody by:
1. Computing SHA-256 + MD5 hashes at ingestion
2. Storing hashes in the SQLite case database
3. Re-verifying hashes on demand
4. Logging all processing steps in the timeline

## Hunt Packs

| Pack | Description | Detection |
|------|-------------|-----------|
| `persistence` | Registry Run keys, services, scheduled tasks, WMI, shell extensions | 5 rules |
| `lateral_movement` | PsExec, WMI, RDP, SMB lateral movement | 4 rules |
| `exfiltration` | DNS tunneling, HTTP upload, cloud storage, archiving | 4 rules |

## AI Triage

The triage system uses two approaches:
1. **Statistical anomaly detection** — temporal bursts, severity distribution, source patterns, attack sequences
2. **LLM summary** — Ollama-powered natural language case summary

Risk scores range from 0-100:
- 75+ → CRITICAL
- 50-74 → HIGH
- 25-49 → MEDIUM
- 10-24 → LOW
- 0-9 → MINIMAL