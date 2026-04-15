# DEADDROP — Digital Forensics Toolkit

> **Status:** SPEC — Awaiting Review  
> **Created:** April 15, 2026  
> **Author:** Agent Mackenzie  
> **Target:** Portfolio project + practical DFIR tool

---

## 1. Why DEADDROP?

**Portfolio gap:** No digital forensics project. This is one of the most fundamental cybersecurity domains — every Security Engineer role asks about DFIR (Digital Forensics & Incident Response).

**Market gap:** Most open-source DFIR tools are either:
- **Monolithic GUIs** (Autopsy — Java, heavy, hard to automate)
- **Fragmented CLIs** (Sleuth Kit, Volatility — separate tools, no unified workflow)
- **Enterprise-only** (Magnet AXIOM, Cellebrite — $5K+ licenses)
- **Single-purpose** (forensic-timeliner, chainsaw — one trick each)

**DEADDROP fills the middle ground:** A unified, automated, CLI-first DFIR toolkit with a modern web dashboard — fast enough for field use, visual enough for reporting, modular enough to extend.

---

## 2. Competitive Landscape

| Tool | Stack | Strength | Weakness |
|------|-------|----------|----------|
| **Autopsy/TSK** | Java/C | Full disk analysis | Monolithic, slow, no API |
| **Volatility3** | Python | Memory forensics standard | CLI-only, no timeline integration |
| **Dissect** (Fox-IT) | Python | Modular, great parsers | AGPL, enterprise-focused, no dashboard |
| **Chainsaw** (WithSecure) | Rust | Fast Windows artifact hunting | Windows-only, single purpose |
| **Forensic Timeliner** | Rust | High-speed timeline engine | CSV-only, no visualization |
| **Velociraptor** | Go | Remote live response | Complex, different use case |

**DEADDROP differentiators:**
- ✅ Unified workflow (disk + memory + logs → one pipeline)
- ✅ Modern React dashboard (not Java Swing)
- ✅ AI-assisted analysis (anomaly detection, auto-triage)
- ✅ Chain-of-custody built-in (hash verification at every step)
- ✅ Automated reporting (HTML + PDF with evidence tags)
- ✅ Plugin system (extend without touching core)

---

## 3. Core Features

### 3.1 Evidence Acquisition & Integrity
- Disk image ingestion: E01, RAW/DD, VMDK, QCOW2, ISO
- Memory dump ingestion: raw, elf64, vmware, windows crash dump
- **Hash verification** at every stage (SHA-256, MD5) — chain of custody
- Write-blocking awareness (detect if evidence was modified)
- Case management (create case, add evidence, track analysts)

### 3.2 Disk Forensics Engine
- Filesystem parsing: NTFS, FAT32, Ext4, APFS (via existing libs)
- Deleted file recovery / file carving (carve by signature: JPEG, PNG, PDF, DOCX, ZIP)
- MFT parsing (Windows Master File Table)
- Registry hive analysis (Windows registry keys: run keys, services, USB artifacts, browser data)
- Prefetch analysis (Windows execution evidence)
- Event log parsing (Windows EVTX → security, system, application)
- Alternate Data Streams (ADS) detection

### 3.3 Memory Forensics
- Volatility3 integration (wrapper, not reimplementation)
- Process listing, network connections, DLL listing
- Registry hive extraction from memory
- Malware IOC scanning (YARA rules against memory)
- Timeline extraction from memory artifacts

### 3.4 Timeline Engine
- Merge artifacts from disk + memory + logs into unified timeline
- Body file format (TSK-compatible)
- CSV/JSON export
- Filter by time range, artifact type, severity
- Super-timeline generation (Plaso-compatible output)

### 3.5 Artifact Hunter
- Pre-built hunt packs: persistence, lateral movement, exfiltration, malware
- YARA rule scanning across disk images and memory
- Regex-based pattern matching for IOCs (IPs, domains, hashes, URLs)
- IOC management (import MISP, STIX, OpenIOC)

### 3.6 AI-Assisted Triage
- Anomaly scoring on timeline events (statistical outlier detection)
- Auto-tag suspicious processes, unusual registry modifications
- Clustering similar events for triage prioritization
- Natural language case summary generation
- **This is the killer feature** — no open-source DFIR tool does this well

### 3.7 Reporting
- Auto-generated case reports (HTML + PDF)
- Evidence tagging and bookmarking
- Timeline visualization (D3.js interactive)
- Artifact screenshots embedded in reports
- Expert witness–ready formatting (case metadata, hash verification log)

### 3.8 Plugin System
- Python plugin interface (`deaddrop.plugins` namespace)
- Hook into pipeline stages: ingest → analyze → hunt → report
- Hot-reload plugins during investigation
- Plugin marketplace (future — local directory for now)

---

## 4. Architecture

```
┌─────────────────────────────────────────────┐
│                 CLI (Click)                  │
│  deaddrop case create | ingest | analyze |   │
│  hunt | timeline | report | plugin           │
└──────────────┬──────────────────────────────┘
               │
┌──────────────▼──────────────────────────────┐
│            Core Engine (Python)              │
│  ┌─────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ Evidence │ │ Disk     │ │ Memory       │ │
│  │ Manager  │ │ Forensics│ │ Forensics    │ │
│  │ (hash,   │ │ (TSK,    │ │ (Volatility3│ │
│  │  case)   │ │  carving)│ │  wrapper)    │ │
│  └────┬─────┘ └────┬─────┘ └──────┬───────┘ │
│       │             │              │         │
│  ┌────▼─────────────▼──────────────▼───────┐ │
│  │         Timeline Engine                 │ │
│  │    (merge, filter, super-timeline)      │ │
│  └────────────────┬────────────────────────┘ │
│                   │                          │
│  ┌────────────────▼────────────────────────┐ │
│  │     Artifact Hunter (YARA + IOC)        │ │
│  └────────────────┬────────────────────────┘ │
│                   │                          │
│  ┌────────────────▼────────────────────────┐ │
│  │     AI Triage (anomaly scoring)         │ │
│  └────────────────┬────────────────────────┘ │
│                   │                          │
│  ┌────────────────▼────────────────────────┐ │
│  │     Report Generator (Jinja2 + Weasy)   │ │
│  └─────────────────────────────────────────┘ │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │     Plugin System (entry_points)         │ │
│  └─────────────────────────────────────────┘ │
└──────────────────┬───────────────────────────┘
                   │
┌──────────────────▼───────────────────────────┐
│         API Server (Fastify + TypeScript)     │
│   REST API + WebSocket for real-time updates │
└──────────────────┬───────────────────────────┘
                   │
┌──────────────────▼───────────────────────────┐
│       Web Dashboard (React + Vite + D3)      │
│  Case overview | Timeline | Artifacts |      │
│  Hunt results | AI Triage | Reports          │
└──────────────────────────────────────────────┘
```

---

## 5. Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Core Engine** | Python 3.12+ | DFIR ecosystem runs on Python (Volatility3, Dissect, Plaso). Ecosystem advantage. |
| **CLI** | Click | De facto standard, composable commands |
| **Disk Forensics** | pytsk3 + dissect | Leverage existing parsers, don't reinvent |
| **Memory Forensics** | Volatility3 (subprocess) | Industry standard, well-maintained |
| **YARA** | yara-python | Native YARA integration |
| **Timeline** | Custom engine + Plaso-compatible output | Merge multiple sources, export standard formats |
| **AI Triage** | scikit-learn + local LLM (Ollama) | Anomaly detection + natural language summaries |
| **API** | Fastify (TypeScript) | Fast, typed, WebSocket support |
| **Dashboard** | React 19 + Vite + Tailwind + D3.js | Modern, fast, interactive visualizations |
| **Reporting** | Jinja2 → HTML, WeasyPrint → PDF | Professional reports with evidence tags |
| **Database** | SQLite (local) | Case data, artifacts, evidence metadata |
| **Plugin System** | Python entry_points (setuptools) | Standard, discoverable, hot-reloadable |
| **Container** | Docker + Docker Compose | Reproducible forensic environment |

---

## 6. CLI Design

```bash
# Case management
deaddrop case create --name "Incident-2026-001" --analyst "Raphael"
deaddrop case list
deaddrop case info <case-id>

# Evidence ingestion
deaddrop ingest disk --image suspect.dd --case <case-id>
deaddrop ingest disk --image suspect.E01 --case <case-id>
deaddrop ingest memory --dump memory.raw --case <case-id>

# Analysis
deaddrop analyze filesystem --case <case-id>          # Parse filesystem, list files
deaddrop analyze registry --case <case-id>            # Windows registry analysis
deaddrop analyze prefetch --case <case-id>            # Prefetch execution analysis
deaddrop analyze events --case <case-id>              # Event log analysis
deaddrop analyze memory --case <case-id>               # Run Volatility3 plugins

# Hunting
deaddrop hunt --yara /rules/suspicious.yar --case <case-id>
deaddrop hunt --ioc iocs.json --case <case-id>
deaddrop hunt --pack persistence --case <case-id>     # Pre-built hunt pack

# Timeline
deaddrop timeline generate --case <case-id>           # Super-timeline
deaddrop timeline export --format csv --case <case-id>
deaddrop timeline filter --from 2026-04-01 --to 2026-04-15

# AI Triage
deaddrop triage --case <case-id>                      # Auto-score anomalies
deaddrop triage --summary --case <case-id>            # Natural language summary

# Reporting
deaddrop report generate --case <case-id> --format html
deaddrop report generate --case <case-id> --format pdf

# Dashboard
deaddrop dashboard --port 8080                        # Launch web UI

# Plugins
deaddrop plugin list
deaddrop plugin install <name>
deaddrop plugin run <name> --case <case-id>
```

---

## 7. Project Structure

```
DEADDROP/
├── SPEC.md                    # This file
├── README.md
├── pyproject.toml             # Python project (uv/pip)
├── docker-compose.yml
├── Dockerfile
│
├── src/
│   └── deaddrop/
│       ├── __init__.py
│       ├── cli/               # Click CLI commands
│       │   ├── __init__.py
│       │   ├── case.py
│       │   ├── ingest.py
│       │   ├── analyze.py
│       │   ├── hunt.py
│       │   ├── timeline.py
│       │   ├── triage.py
│       │   ├── report.py
│       │   └── dashboard.py
│       │
│       ├── core/              # Core engine
│       │   ├── evidence.py    # Evidence manager, hash verification
│       │   ├── case.py        # Case management, SQLite
│       │   └── config.py      # Configuration
│       │
│       ├── disk/              # Disk forensics
│       │   ├── filesystem.py  # Filesystem parsing (pytsk3)
│       │   ├── carving.py     # File carving
│       │   ├── registry.py    # Windows registry
│       │   ├── prefetch.py    # Prefetch analysis
│       │   ├── events.py      # Event log parsing
│       │   └── mft.py         # MFT parsing
│       │
│       ├── memory/            # Memory forensics
│       │   ├── volatility.py  # Volatility3 wrapper
│       │   └── analyzer.py    # Memory artifact extraction
│       │
│       ├── timeline/          # Timeline engine
│       │   ├── engine.py      # Merge, sort, filter
│       │   ├── bodyfile.py    # TSK body file format
│       │   └── export.py      # CSV/JSON/Plaso output
│       │
│       ├── hunt/              # Artifact hunting
│       │   ├── yara_scanner.py
│       │   ├── ioc_matcher.py
│       │   └── packs/         # Pre-built hunt packs
│       │       ├── persistence.yaml
│       │       ├── lateral_movement.yaml
│       │       └── exfiltration.yaml
│       │
│       ├── triage/            # AI-assisted triage
│       │   ├── anomaly.py     # Statistical anomaly detection
│       │   ├── scorer.py      # Severity scoring
│       │   └── llm.py         # LLM summary (Ollama)
│       │
│       ├── report/            # Reporting
│       │   ├── generator.py   # Report generation
│       │   ├── templates/     # Jinja2 templates
│       │   │   ├── case_report.html
│       │   │   └── evidence_tag.html
│       │   └── pdf.py         # WeasyPrint PDF export
│       │
│       └── plugins/           # Plugin system
│           ├── manager.py     # Plugin loader
│           ├── hooks.py       # Pipeline hooks
│           └── builtin/       # Shipped plugins
│
├── server/                    # API server (TypeScript)
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── index.ts           # Fastify entry
│   │   ├── routes/
│   │   │   ├── cases.ts
│   │   │   ├── evidence.ts
│   │   │   ├── timeline.ts
│   │   │   ├── artifacts.ts
│   │   │   ├── hunt.ts
│   │   │   └── reports.ts
│   │   ├── ws/
│   │   │   └── events.ts      # WebSocket real-time
│   │   └── services/          # Python bridge
│   └── docker/
│       └── Dockerfile
│
├── dashboard/                 # React dashboard
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── CaseOverview.tsx
│   │   │   ├── TimelineView.tsx     # D3 interactive
│   │   │   ├── ArtifactTable.tsx
│   │   │   ├── HuntResults.tsx
│   │   │   ├── TriagePanel.tsx
│   │   │   └── ReportPreview.tsx
│   │   ├── hooks/
│   │   ├── api/
│   │   └── styles/
│   └── Dockerfile
│
├── rules/                     # YARA rules
│   ├── malware/
│   ├── persistence/
│   └── suspicious/
│
├── tests/
│   ├── test_evidence.py
│   ├── test_timeline.py
│   ├── test_hunt.py
│   └── fixtures/              # Test disk images (NIST sample)
│
└── docs/
    ├── architecture.md
    ├── plugin-development.md
    └── user-guide.md
```

---

## 8. Build Phases

### Phase 1 — Core Engine + CLI (Foundation)
**Scope:** Case management, evidence ingestion, hash verification, CLI skeleton  
**Deliverables:**
- `deaddrop case create/list/info`
- `deaddrop ingest disk/memory`
- SQLite case database
- SHA-256 hash verification at ingest
- Basic filesystem listing via pytsk3

### Phase 2 — Analysis + Timeline (Deep Analysis)
**Scope:** Disk forensics, memory forensics, timeline engine  
**Deliverables:**
- Filesystem, registry, prefetch, event log parsing
- Volatility3 wrapper (process list, network connections, DLLs)
- Timeline engine (merge, filter, export)
- `deaddrop analyze *` and `deaddrop timeline *` commands

### Phase 3 — Hunting + AI Triage (Intelligence)
**Scope:** YARA scanning, IOC matching, anomaly detection, LLM summaries  
**Deliverables:**
- YARA scanner across disk images and memory
- Pre-built hunt packs (persistence, lateral movement, exfiltration)
- IOC matcher (IP, domain, hash, URL)
- Anomaly scoring on timeline events
- LLM-powered case summary (Ollama)
- `deaddrop hunt` and `deaddrop triage` commands

### Phase 4 — Dashboard + Reporting (Presentation)
**Scope:** API server, React dashboard, report generation  
**Deliverables:**
- Fastify REST API + WebSocket
- React dashboard with D3 timeline visualization
- HTML + PDF report generation
- `deaddrop report` and `deaddrop dashboard` commands
- Docker Compose for full stack
- Plugin system (entry_points)

---

## 9. Key Dependencies

```toml
[project]
dependencies = [
    "click>=8.1",
    "pytsk3>=20240101",       # Sleuth Kit Python bindings
    "yara-python>=4.5",
    "volatility3>=2.7",       # Memory forensics
    "scikit-learn>=1.5",      # Anomaly detection
    "jinja2>=3.1",            # Report templates
    "weasyprint>=62",         # PDF generation
    "rich>=13",                # CLI formatting
    "sqlite-utils>=3.36",     # SQLite helper
    "pydantic>=2.0",          # Data validation
    "httpx>=0.27",            # HTTP client (for API bridge)
]
```

---

## 10. What Makes This Portfolio-Ready

| What Employers Want | How DEADDROP Demonstrates It |
|---------------------|------------------------------|
| DFIR methodology | Chain of custody, evidence integrity, proper acquisition flow |
| Tool familiarity | TSK, Volatility, YARA — shows you know the standards |
| Automation skills | CLI-first, plugin system, pipeline automation |
| Modern development | TypeScript API, React dashboard, Docker |
| AI/ML in security | Anomaly detection, LLM triage — cutting edge |
| Reporting quality | Professional reports — communication matters |
| Full-stack ability | Python engine + TS server + React UI + Docker |

---

## 11. Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Reinventing the wheel vs. Dissect | Don't compete on parsers. Wrap existing libs. Value is in the unified workflow + AI + dashboard |
| E01 format complexity | Use pytsk3/libewf — don't parse raw |
| Memory forensics scope creep | Wrap Volatility3, don't reimpl. Clear boundary |
| AI triage false positives | Score + explain, don't auto-delete. Human always in loop |
| Large evidence files | Stream processing, don't load into RAM. SQLite for metadata |

---

## 12. Success Criteria

- [ ] Ingest E01 and RAW disk images, verify hash chain
- [ ] Parse NTFS filesystem, list deleted files, carve JPEG/PDF
- [ ] Run Volatility3 plugins through unified CLI
- [ ] Generate merged timeline from disk + memory + logs
- [ ] YARA scan with 10+ rules, detect EICAR test file
- [ ] AI triage scores anomalies with >70% precision on test data
- [ ] Generate HTML report with embedded evidence
- [ ] Dashboard shows interactive D3 timeline
- [ ] 3+ plugins in builtin directory
- [ ] Docker Compose brings up full stack with one command
- [ ] README with install + usage + screenshots
- [ ] GitHub repo with CI (pytest + lint)

---

_This spec is ready for review. Once approved, Phase 1 build can begin._