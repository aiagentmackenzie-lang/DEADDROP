"""Tests for ReportGenerator — HTML/PDF forensic reports."""

import pytest
from pathlib import Path

from deaddrop.core.case import CaseManager
from deaddrop.report.generator import ReportGenerator


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


@pytest.fixture
def populated_case(case_mgr):
    """Create a case with evidence, artifacts, and timeline entries."""
    c = case_mgr.create_case("Report Test", analyst="Raphael", notes="Testing reports")
    case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1048576, "a" * 64, "b" * 32, "RAW")
    case_mgr.add_evidence(c.id, "ev2", "memory", "/tmp/mem.raw", "mem.raw", 2097152, "c" * 64, "d" * 32, "RAW")
    case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-15T10:00:00", "Suspicious file found", "high")
    case_mgr.add_artifact(c.id, "ev2", "memory", "process", "2026-01-15T10:05:00", "Mimikatz detected", "critical")
    case_mgr.add_timeline_entry(c.id, "events", "2026-01-15T10:00:00", "Logon event", "info")
    case_mgr.add_timeline_entry(c.id, "memory", "2026-01-15T10:05:00", "Process injection", "high")
    case_mgr.add_hunt_result(c.id, "hr1", "EICAR_Test", "yara", severity="info")
    return c


class TestReportGenerator:
    def test_generate_html_report(self, case_mgr, populated_case, tmp_path):
        """Generate an HTML report and verify it exists and contains key data."""
        gen = ReportGenerator(case_mgr)
        output = str(tmp_path / "report.html")
        path = gen.generate(populated_case.id, "html", output)
        assert Path(path).exists()

        content = Path(path).read_text()
        assert "Report Test" in content
        assert "img.raw" in content
        assert "mem.raw" in content
        assert "Mimikatz" in content
        assert "Chain of Custody" in content

    def test_generate_pdf_fallback(self, case_mgr, populated_case, tmp_path):
        """PDF generation falls back to HTML when weasyprint unavailable."""
        gen = ReportGenerator(case_mgr)
        output = str(tmp_path / "report.pdf")
        path = gen.generate(populated_case.id, "pdf", output)
        # When weasyprint is unavailable, it falls back to HTML
        # The returned path will end with .html (possibly with a note)
        html_path = path.split(" ")[0]  # Strip any appended message
        assert Path(html_path).exists()
        # Verify it contains actual report content
        content = Path(html_path).read_text()
        assert "DEADDROP" in content or "Forensic" in content

    def test_generate_report_auto_path(self, case_mgr, populated_case):
        """Report generates to auto-created directory when no output path given."""
        gen = ReportGenerator(case_mgr)
        path = gen.generate(populated_case.id, "html")
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "DEADDROP" in content

    def test_report_nonexistent_case(self, case_mgr):
        """Generating a report for nonexistent case raises ValueError."""
        gen = ReportGenerator(case_mgr)
        with pytest.raises(ValueError, match="not found"):
            gen.generate("nonexistent", "html")

    def test_report_contains_severity(self, case_mgr, populated_case, tmp_path):
        """Report contains severity distribution."""
        gen = ReportGenerator(case_mgr)
        output = str(tmp_path / "sev_report.html")
        path = gen.generate(populated_case.id, "html", output)
        content = Path(path).read_text()
        assert "CRITICAL" in content
        assert "HIGH" in content