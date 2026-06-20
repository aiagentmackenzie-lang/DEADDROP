"""Tests for timeline engine."""

from pathlib import Path

import pytest

from deaddrop.core.case import CaseManager
from deaddrop.timeline.engine import TimelineEngine
from deaddrop.timeline.export import TimelineExporter


@pytest.fixture
def case_mgr(tmp_path):
    mgr = CaseManager(tmp_path / "test.db")
    yield mgr
    mgr.close()


class TestTimelineEngine:
    def test_generate_empty(self, case_mgr):
        case = case_mgr.create_case("Test")
        engine = TimelineEngine(case_mgr)
        result = engine.generate(case.id)
        assert result["total_entries"] == 0

    def test_generate_with_entries(self, case_mgr):
        case = case_mgr.create_case("Test")
        case_mgr.add_timeline_entry(case.id, "events", "2026-04-15T10:00:00Z", "Test event", "info")
        case_mgr.add_timeline_entry(case.id, "filesystem", "2026-04-15T11:00:00Z", "File found", "info")
        engine = TimelineEngine(case_mgr)
        result = engine.generate(case.id)
        assert result["total_entries"] == 2
        assert "events" in result["sources"]
        assert "filesystem" in result["sources"]

    def test_filter_entries(self, case_mgr):
        case = case_mgr.create_case("Test")
        case_mgr.add_timeline_entry(case.id, "events", "2026-04-15T10:00:00Z", "Event 1")
        case_mgr.add_timeline_entry(case.id, "filesystem", "2026-04-15T11:00:00Z", "File 1")
        engine = TimelineEngine(case_mgr)
        entries = engine.filter_entries(case.id, source="events")
        assert len(entries) == 1
        assert entries[0]["source"] == "events"

    def test_stats(self, case_mgr):
        case = case_mgr.create_case("Test")
        case_mgr.add_timeline_entry(case.id, "events", "2026-04-15T10:00:00Z", "Event 1", "high")
        case_mgr.add_timeline_entry(case.id, "events", "2026-04-15T11:00:00Z", "Event 2", "info")
        engine = TimelineEngine(case_mgr)
        stats = engine.get_stats(case.id)
        assert stats["total"] == 2
        assert stats["severity_counts"]["high"] == 1


class TestTimelineExport:
    def test_export_csv(self, case_mgr, tmp_path):
        case = case_mgr.create_case("Test")
        case_mgr.add_timeline_entry(case.id, "events", "2026-04-15T10:00:00Z", "Event 1")
        exporter = TimelineExporter(case_mgr)
        path = exporter.export(case.id, "csv", str(tmp_path / "timeline.csv"))
        assert Path(path).exists()
        content = Path(path).read_text()
        assert "timestamp" in content
        assert "Event 1" in content

    def test_export_json(self, case_mgr, tmp_path):
        case = case_mgr.create_case("Test")
        case_mgr.add_timeline_entry(case.id, "events", "2026-04-15T10:00:00Z", "Event 1")
        exporter = TimelineExporter(case_mgr)
        path = exporter.export(case.id, "json", str(tmp_path / "timeline.json"))
        assert Path(path).exists()

    def test_export_body(self, case_mgr, tmp_path):
        case = case_mgr.create_case("Test")
        case_mgr.add_timeline_entry(case.id, "events", "2026-04-15T10:00:00Z", "Event 1")
        exporter = TimelineExporter(case_mgr)
        path = exporter.export(case.id, "body", str(tmp_path / "timeline.body"))
        assert Path(path).exists()
