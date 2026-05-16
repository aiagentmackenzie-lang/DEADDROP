# DEADDROP README Audit — Claims vs Reality

**Auditor:** Agent Mackenzie | **Date:** 2026-05-16

---

## ❌ MISMATCHES FOUND

| # | README Claim | Reality | Severity |
|---|-------------|--------|----------|
| 1 | Test badge: "89 passing" | **128 tests** (39 new from bug fix audit) | Stale badge |
| 2 | `deaddrop dashboard --port 8080` works | **Broken** — imports `deaddrop.dashboard_server` which doesn't exist. `subprocess.run([sys.executable, "-m", "deaddrop.dashboard_server", ...])` crashes with `ModuleNotFoundError` | 🔴 Broken feature |
| 3 | CLI `--pack malware` option | No `malware.yaml` hunt pack exists in `src/deaddrop/hunt/packs/`. Only persistence, lateral_movement, exfiltration packs exist. CLI will return "Hunt pack 'malware' not found" | 🟠 Broken CLI option |
| 4 | "Run 'deaddrop setup' first" | No `setup` CLI command exists. Phantom reference. | 🟡 Misleading error message |
| 5 | `weasyprint>=62` as core dependency | Should be optional — heavy system deps (pango, gdk-pixbuf). Code already handles ImportError gracefully | 🟡 Packaging issue |
| 6 | `scikit-learn>=1.5` as core dependency | **Never imported anywhere** in codebase. Dead dependency. | 🟠 Dead dependency |
| 7 | `sqlite-utils>=3.36` as core dependency | **Never imported anywhere** in codebase. Dead dependency. | 🟠 Dead dependency |
| 8 | "Windows Minidump" in format table | `.dmp` maps to "Windows Crash Dump" in FORMAT_NAMES, not "Windows Minidump". MDMP magic is detected but extension mapping is different | 🟢 Minor naming mismatch |
| 9 | Evidence format table lists "Windows Minidump" separately | Not a separate supported format — just a magic-byte variant of .dmp | 🟢 Minor |

## ✅ VERIFIED CORRECT

| Claim | Status |
|-------|--------|
| Python 3.12+ | ✅ `requires-python = ">=3.12"` |
| Click CLI | ✅ All commands use Click decorators |
| Fastify API server (TypeScript) | ✅ `server/src/index.ts` with Fastify 5, routes, WebSocket |
| React 19 + D3 dashboard | ✅ `dashboard/package.json` + `TimelineView.tsx` with D3 interactive timeline |
| Docker / docker-compose | ✅ `Dockerfile` + `docker-compose.yml` (3 services: engine, server, dashboard) |
| 28 Windows security events | ✅ `SECURITY_EVENTS` dict has exactly 28 entries |
| Disk formats (RAW/DD, E01, VMDK, QCOW2, ISO, IMG) | ✅ All in `SUPPORTED_DISK_FORMATS` |
| Memory formats (RAW, VMEM, Crash Dump, ELF64) | ✅ All in `SUPPORTED_MEMORY_FORMATS` + magic detection |
| Magic byte detection (EWF, KDMV, QFI\xfb, ELF, MDMP, PAGE) | ✅ All in `detect_format()` |
| Case CRUD (create, list, info, close) | ✅ CLI commands exist and work |
| Ingest disk/memory | ✅ CLI commands + EvidenceManager |
| Analyze filesystem/registry/prefetch/events/memory | ✅ All 5 CLI commands exist |
| Hunt YARA + IOC | ✅ CLI command with --yara, --ioc, --pack options |
| Triage run + summary | ✅ CLI commands exist |
| Timeline generate/export/filter | ✅ CLI commands exist |
| Report HTML/PDF | ✅ CLI command with html/pdf choice |
| Plugin system | ✅ PluginManager + 3 builtins |
| Hunt packs (persistence, lateral_movement, exfiltration) | ✅ YAML packs exist |
| YARA rules (malware, persistence, suspicious) | ✅ rules/ directory with .yar files |
| Chain of custody (SHA-256 + MD5) | ✅ `compute_hashes()` + verification |
| Streaming file carving (4MB chunks) | ✅ `FileCarver._read_chunks()` with CHUNK_SIZE |
| No hallucinated artifacts | ✅ Empty list returns documented |
| MIT License | ✅ `pyproject.toml` says MIT (but LICENSE file missing!) |
| Project structure matches | ✅ All directories exist |

## ⚠️ ADDITIONAL ISSUES

| # | Issue | Detail |
|---|-------|--------|
| A | No LICENSE file | README links to LICENSE but file doesn't exist. pyproject.toml declares MIT. |
| B | `dashboard_server` module missing | The dashboard CLI command is completely non-functional |
| C | Heavy unnecessary dependencies | scikit-learn (110MB+) and sqlite-utils pulled in for nothing |