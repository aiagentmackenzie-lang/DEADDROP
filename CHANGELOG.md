# Changelog

All notable changes to DEADDROP. Dates are YYYY-MM-DD. The format is based on
Keep a Changelog, and this project adheres to Semantic Versioning.

## [1.2.0] — 2026-06-20 — Production-grade hardening (Mackenzie, lead)

A from-scratch handover audit (Claude Opus reviewing) found that the prior
v1.0/v1.1 "20 bugs fixed" audit had fixed real engine-core bugs but missed the
ship-blockers and labeled several bugs as "documented limitations" to ship
green checkmarks. This release fixes the real blockers, removes the broken web
stack, and makes the forensic parsers actually work.

### Breaking
- Removed the Node (Fastify) API server entirely (`server/` deleted). It
  shelled out to the `deaddrop` CLI and `JSON.parse`d Rich-formatted console
  output, returning `{raw: "<ansi>"}` for every call — the dashboard never
  worked. Replaced with an in-process FastAPI app.
- `Config.server_host` default `0.0.0.0` → `127.0.0.1` (do not bind open by
  default).
- `ReportGenerator.generate` now refuses to render against tampered or missing
  evidence (chain-of-custody gate). Pass `skip_verify=True` to override.
- `CaseManager.update_case` now rejects (returns False + logs) when any unknown
  column is passed, instead of silently filtering it.
- Bundled YARA rules moved from `rules/` (repo root) into `src/deaddrop/rules/`
  (package data, resolved via `importlib.resources`).

### Added
- **FastAPI API** (`src/deaddrop/api/`): in-process REST + WebSocket. Pydantic
  body validation, bearer-token auth (`DEADDROP_API_TOKEN`), CORS allowlist,
  rate limiting on expensive endpoints, real WebSocket event bus (case
  lifecycle events + heartbeats), serves the built dashboard at `/`.
- **Tamper-evident audit log** (`src/deaddrop/core/audit.py`): append-only
  JSONL with a SHA-256 hash chain, stored outside the SQLite DB. Every
  `CaseManager` mutation is audited; `verify_audit_log()` detects tampering.
- **Real forensic parsers**: `EventLogAnalyzer` (python-evtx), `RegistryAnalyzer`
  (python-registry), spec-conformant SCCA `PrefetchAnalyzer`. All three scan a
  directory of extracted artifacts or a standalone file.
- **Stateful cross-chunk file carving** — files whose footer spans a chunk
  boundary are now recovered (was silently dropped).
- **Chunked YARA scanning** for disk images > 2 GiB (overlapping windows, deduped
  hits) — no more silent skip of large images.
- **Directory evidence ingestion** with a sorted-manifest hash for
  chain-of-custody on folders of extracted artifacts.
- **Chain-of-custody integrity gate** on report generation.
- **`DEADDROP_HOME` env override** for test/operator isolation.
- `.env.example`, `.dockerignore`.
- `tests/test_api.py`, `tests/test_phase1.py`, `tests/test_phase3.py`,
  `tests/test_phase4.py`, `tests/test_plugins.py`.
- Honest README status table (✅/⚠️/❌) per feature.

### Fixed
- **Plugin manager crashed** (`deaddrop plugin list` raised
  `AttributeError: module 'importlib' has no attribute 'util'`) — `import
  importlib.util` is now explicit. Prior audits never ran the command.
- **Two failing PDF tests** assumed WeasyPrint absent; it ships in the venv.
  Tests now branch on availability and assert real `%PDF-` magic when present.
- **EICAR builtin YARA rule never compiled** (`\P` invalid escape) — fixed
  escaping; the rule now compiles and matches.
- **MFT `$FILE_NAME`** read the name from a hardcoded 66-byte offset; now reads
  the content offset from the attribute header (same pattern as the
  `$STANDARD_INFORMATION` fix).
- **Prefetch parser** used invented offsets (run_count@68, name@112/8) with
  tautology tests. Now spec-conformant (name@0x10, run_count@0x90) with tests
  built from literal spec offsets.
- **`detect_format`** returned `"Windows Minidump"` for MDMP magic but
  `"Windows Crash Dump"` for `.dmp` extension — unified to `"Windows Crash Dump"`.
- **`FilesystemAnalyzer.walk_dir`** had no depth cap and built the full entries
  list before slicing — added `MAX_ENTRIES`/`MAX_DEPTH` with early bail.
- **`CaseManager.delete_case`** is now transactional (BEGIN IMMEDIATE + ordered
  child deletes + commit/rollback). Schema FKs declare `ON DELETE CASCADE`
  (case_id) and `ON DELETE SET NULL` (evidence_id).
- **LLM summarizer** swallowed Ollama failures silently — now logs a WARNING
  before the rule-based fallback.
- **PDF report `except` clause** was `except (ImportError, OSError, Exception)`
  (the `Exception` masked real bugs as "PDF unavailable") — narrowed to
  `ImportError, OSError`; other exceptions propagate.
- **Severity validation** at the DB boundary
  (`CaseManager._normalize_severity`) — invalid values (e.g. from YARA rule
  metadata) normalize to a default with a WARNING, preventing triage/report
  poisoning.
- Tracked `.pyc` removed from git; `mypy` installed and the type gate enforced.

### Quality gate
- `ruff check src/ tests/` → clean (pragmatic rule set: E/F/W/I/UP/B/SIM/C4/PIE/RUF).
- `mypy src` → clean (47 files; `check_untyped_defs`, `warn_return_any`, etc.).
- `pytest` → 196 passing (was 126 + 2 failing).

## [1.1.0] — 2026-05-16 — Prior audit (partial)

Engine-core bug fixes (C-01 XSS, C-02 SQLi whitelist, C-03 RFC 1918, H-03
Volatility plugin whitelist, H-04 WAL/FK, M-05 UUID, M-06 Bessel's correction,
etc.). The web stack and several parsers remained broken (see 1.2.0). The
`BUG_CATALOG.md` and `README_AUDIT.md` from this audit are retained on disk
(gitignored) as historical reference.

## [1.0.0] — 2026-04-15 — Initial release

Initial DFIR toolkit: CLI, disk/memory/timeline/hunt/triage/report modules,
Node API server (broken — see 1.2.0), React dashboard.