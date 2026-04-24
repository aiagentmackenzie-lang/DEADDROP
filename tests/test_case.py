"""Tests for CaseManager — CRUD, evidence, artifacts, timeline, hunt results."""

import pytest

from deaddrop.core.case import CaseManager


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test_cases.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


class TestCaseCreation:
    def test_create_case_defaults(self, case_mgr):
        case = case_mgr.create_case("Incident-001")
        assert case.id
        assert case.name == "Incident-001"
        assert case.status == "open"
        assert case.analyst == ""
        assert case.notes == ""

    def test_create_case_with_analyst(self, case_mgr):
        case = case_mgr.create_case("Case Alpha", analyst="Raphael", notes="Initial notes")
        assert case.analyst == "Raphael"
        assert case.notes == "Initial notes"

    def test_create_multiple_cases(self, case_mgr):
        c1 = case_mgr.create_case("Case 1")
        c2 = case_mgr.create_case("Case 2")
        assert c1.id != c2.id


class TestCaseRetrieval:
    def test_get_case(self, case_mgr):
        created = case_mgr.create_case("Find Me", analyst="Alice")
        found = case_mgr.get_case(created.id)
        assert found is not None
        assert found.id == created.id
        assert found.name == "Find Me"

    def test_get_case_not_found(self, case_mgr):
        result = case_mgr.get_case("nonexistent")
        assert result is None

    def test_list_cases(self, case_mgr):
        case_mgr.create_case("First")
        case_mgr.create_case("Second")
        cases = case_mgr.list_cases()
        assert len(cases) == 2

    def test_list_cases_by_status(self, case_mgr):
        case_mgr.create_case("Open Case")
        cases = case_mgr.list_cases(status="open")
        assert len(cases) == 1
        cases = case_mgr.list_cases(status="closed")
        assert len(cases) == 0


class TestCaseUpdate:
    def test_close_case(self, case_mgr):
        c = case_mgr.create_case("Close Me")
        assert case_mgr.close_case(c.id) is True
        found = case_mgr.get_case(c.id)
        assert found.status == "closed"

    def test_close_nonexistent(self, case_mgr):
        assert case_mgr.close_case("nope") is False

    def test_update_case_fields(self, case_mgr):
        c = case_mgr.create_case("Original")
        case_mgr.update_case(c.id, name="Updated", analyst="Bob")
        found = case_mgr.get_case(c.id)
        assert found.name == "Updated"
        assert found.analyst == "Bob"

    def test_update_sets_timestamp(self, case_mgr):
        c = case_mgr.create_case("Timestamp Test")
        import time
        time.sleep(0.01)
        case_mgr.update_case(c.id, notes="updated")
        found = case_mgr.get_case(c.id)
        assert found.updated_at >= c.created_at

    def test_update_empty_kwargs(self, case_mgr):
        c = case_mgr.create_case("No Update")
        assert case_mgr.update_case(c.id) is False


class TestCaseDelete:
    def test_delete_case_cascades(self, case_mgr):
        c = case_mgr.create_case("Delete Me")
        # Add evidence, artifacts, timeline, hunt results
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1024, "sha", "md5", "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "test")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01", "event1")
        case_mgr.add_hunt_result(c.id, "hr1", "rule1", "yara")

        assert case_mgr.delete_case(c.id) is True
        assert case_mgr.get_case(c.id) is None
        assert case_mgr.list_evidence(c.id) == []
        assert case_mgr.list_artifacts(c.id) == []
        assert case_mgr.get_timeline(c.id) == []
        assert case_mgr.get_hunt_results(c.id) == []

    def test_delete_nonexistent(self, case_mgr):
        assert case_mgr.delete_case("nope") is False


class TestCaseToDict:
    def test_to_dict(self, case_mgr):
        c = case_mgr.create_case("Dict Test", analyst="Ana")
        d = c.to_dict()
        assert d["name"] == "Dict Test"
        assert d["analyst"] == "Ana"
        assert d["status"] == "open"
        assert "id" in d
        assert "created_at" in d


class TestEvidenceCRUD:
    def test_add_and_list_evidence(self, case_mgr):
        c = case_mgr.create_case("Evidence Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 4096, "sha256abc", "md5def", "RAW")
        evidence = case_mgr.list_evidence(c.id)
        assert len(evidence) == 1
        assert evidence[0]["filename"] == "img.raw"
        assert evidence[0]["type"] == "disk"
        assert evidence[0]["sha256"] == "sha256abc"
        assert evidence[0]["verified"] == 1

    def test_list_evidence_empty(self, case_mgr):
        c = case_mgr.create_case("No Evidence")
        assert case_mgr.list_evidence(c.id) == []


class TestArtifactCRUD:
    def test_add_and_list_artifacts(self, case_mgr):
        c = case_mgr.create_case("Artifact Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1024, "sha", "md5", "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "Found file", "medium")
        artifacts = case_mgr.list_artifacts(c.id)
        assert len(artifacts) == 1
        assert artifacts[0]["description"] == "Found file"
        assert artifacts[0]["severity"] == "medium"

    def test_filter_artifacts_by_source(self, case_mgr):
        c = case_mgr.create_case("Filter Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1024, "sha", "md5", "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "FS artifact")
        case_mgr.add_artifact(c.id, "ev1", "memory", "proc", "2026-01-02", "Mem artifact")
        fs_only = case_mgr.list_artifacts(c.id, source="filesystem")
        assert len(fs_only) == 1
        assert fs_only[0]["source"] == "filesystem"


class TestTimelineCRUD:
    def test_add_and_get_timeline(self, case_mgr):
        c = case_mgr.create_case("Timeline Test")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01T10:00:00", "Event 1", "info")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01T11:00:00", "Event 2", "high")
        timeline = case_mgr.get_timeline(c.id)
        assert len(timeline) == 2

    def test_timeline_date_filtering(self, case_mgr):
        c = case_mgr.create_case("Date Filter Test")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01T10:00:00", "Early")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-05T10:00:00", "Late")
        from_ts = "2026-01-03T00:00:00"
        filtered = case_mgr.get_timeline(c.id, from_ts=from_ts)
        assert len(filtered) == 1
        assert filtered[0]["description"] == "Late"

    def test_timeline_ordered_by_timestamp(self, case_mgr):
        c = case_mgr.create_case("Order Test")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-05T10:00:00", "Second")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01T10:00:00", "First")
        timeline = case_mgr.get_timeline(c.id)
        assert timeline[0]["description"] == "First"


class TestHuntResults:
    def test_add_and_get_hunt_results(self, case_mgr):
        c = case_mgr.create_case("Hunt Test")
        case_mgr.add_hunt_result(c.id, "hr1", "EICAR_Test", "yara", severity="critical")
        case_mgr.add_hunt_result(c.id, "hr2", "evil.com", "ioc", severity="high")
        results = case_mgr.get_hunt_results(c.id)
        assert len(results) == 2

    def test_hunt_results_ordered_by_date(self, case_mgr):
        c = case_mgr.create_case("Hunt Order Test")
        case_mgr.add_hunt_result(c.id, "hr1", "Rule1", "yara")
        import time
        time.sleep(0.01)
        case_mgr.add_hunt_result(c.id, "hr2", "Rule2", "yara")
        results = case_mgr.get_hunt_results(c.id)
        # Most recent first
        assert results[0]["rule_name"] == "Rule2"