"""Phase 1 regression tests — locks the cheap ship-blocker fixes.

Covers: H-1 (narrow PDF except), H-2 (Ollama failure logged), H-3 (CaseManager
context manager), H-7 (severity normalization), and the run_plugin return shape.
"""

from __future__ import annotations

import logging
import sqlite3

import pytest

from deaddrop.core.case import CaseManager


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


class TestH7SeverityNormalization:
    """H-7: invalid severity values are normalized at the DB boundary."""

    def test_add_artifact_normalizes_invalid_severity(self, case_mgr, caplog):
        c = case_mgr.create_case("Sev Test")
        with caplog.at_level(logging.WARNING, logger="deaddrop.core.case"):
            aid = case_mgr.add_artifact(
                c.id, None, "test", "cat", "", "desc",
                severity='"><script>',  # would break CSS / poison triage
            )
        assert aid
        arts = case_mgr.list_artifacts(c.id)
        assert arts[0]["severity"] == "info"  # normalized to default
        assert any(r.levelno >= logging.WARNING for r in caplog.records)

    def test_add_hunt_result_normalizes_invalid_severity(self, case_mgr):
        c = case_mgr.create_case("Sev Hunt Test")
        case_mgr.add_hunt_result(
            c.id, "r1", "rule", "yara", severity="bogus",
        )
        results = case_mgr.get_hunt_results(c.id)
        assert results[0]["severity"] == "medium"  # hunt default

    def test_add_timeline_entry_normalizes_invalid_severity(self, case_mgr):
        c = case_mgr.create_case("Sev TL Test")
        case_mgr.add_timeline_entry(
            c.id, "src", "2026-01-01T00:00:00", "d", severity="nonsense",
        )
        tl = case_mgr.get_timeline(c.id)
        assert tl[0]["severity"] == "info"

    def test_valid_severities_pass_through(self, case_mgr):
        c = case_mgr.create_case("Sev Valid Test")
        for sev in ("info", "low", "medium", "high", "critical"):
            case_mgr.add_artifact(c.id, None, "s", "c", "", f"d-{sev}", severity=sev)
        arts = case_mgr.list_artifacts(c.id)
        found = {a["severity"] for a in arts}
        assert found == {"info", "low", "medium", "high", "critical"}


class TestH3ContextManager:
    """H-3: CaseManager supports `with` and closes the connection on exit."""

    def test_context_manager_closes(self, tmp_path):
        db = tmp_path / "ctx.db"
        with CaseManager(db) as mgr:
            mgr.create_case("Ctx Test")
            assert mgr.conn.total_changes >= 1
        # After exit, the connection is closed; further use raises ProgrammingError
        with pytest.raises(sqlite3.ProgrammingError):
            mgr.list_cases()

    def test_context_manager_returns_self(self, tmp_path):
        db = tmp_path / "ctx2.db"
        with CaseManager(db) as mgr:
            assert mgr is not None
            assert isinstance(mgr, CaseManager)


class TestH2OllamaFailureLogged:
    """H-2: Ollama failures are logged before falling back to rule summary."""

    def test_summary_logs_when_ollama_unreachable(self, case_mgr, caplog, monkeypatch):
        from deaddrop.triage.llm import LLMSummarizer

        c = case_mgr.create_case("LLM Fail Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/x.raw", "x.raw", 1024,
                              "a" * 64, "b" * 32, "RAW")

        summarizer = LLMSummarizer(case_mgr, ollama_url="http://127.0.0.1:1", model="x")

        # Force _call_ollama to raise to simulate unreachable Ollama
        def _boom(_ctx):
            raise ConnectionError("Ollama down")

        monkeypatch.setattr(summarizer, "_call_ollama", _boom)

        with caplog.at_level(logging.WARNING, logger="deaddrop.triage.llm"):
            summary = summarizer.summarize(c.id)

        # Falls back to rule-based summary
        assert "DEADDROP Case Summary" in summary or "Case Summary" in summary
        # And logs the failure reason (H-2: was silent before)
        assert any(
            "Ollama" in r.getMessage() and r.levelno >= logging.WARNING
            for r in caplog.records
        ), "Ollama failure must be logged (H-2 fix)"


class TestH1PDFExceptNarrow:
    """H-1: the PDF except clause is narrowed to ImportError/OSError.

    A real programming error (e.g. ValueError from a broken HTML template) must
    NOT be silently masked as "PDF unavailable" — it should propagate.
    """

    def test_pdf_propagates_unexpected_errors(self, case_mgr, tmp_path, monkeypatch):
        from deaddrop.report.generator import ReportGenerator

        c = case_mgr.create_case("PDF Err Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/x.raw", "x.raw", 1024,
                              "a" * 64, "b" * 32, "RAW")
        case_mgr.add_artifact(c.id, "ev1", "hunt", "yara", "", "hit", "high")

        gen = ReportGenerator(case_mgr)

        # Patch weasyprint.HTML.write_pdf to raise a non-Import/OSError
        import builtins
        real_import = builtins.__import__

        class _FakeHTML:
            def __init__(self, *a, **k):
                pass

            def write_pdf(self, path):
                raise ValueError("simulated programming error in PDF render")

        def _import(name, *args, **kwargs):
            if name == "weasyprint" or name.startswith("weasyprint."):
                mod = type(real_import("os"))("weasyprint")
                mod.HTML = _FakeHTML
                return mod
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _import)

        # A ValueError must propagate (not be swallowed into HTML fallback)
        with pytest.raises(ValueError, match="simulated programming error"):
            gen.generate(c.id, "pdf", str(tmp_path / "out.pdf"))


class TestRunPluginReturnShape:
    """run_plugin returns a consistent {success, ...} dict for all outcomes."""

    def test_unknown_plugin_returns_success_false(self):
        from deaddrop.core.config import Config
        from deaddrop.plugins.manager import PluginManager

        pm = PluginManager(Config.load())
        result = pm.run_plugin("nonexistent-plugin-xyz", "any-case")
        assert "success" in result
        assert result["success"] is False
        assert "error" in result
