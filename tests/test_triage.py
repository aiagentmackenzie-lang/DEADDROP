"""Tests for TriageScorer and AnomalyDetector."""

import pytest

from deaddrop.core.case import CaseManager
from deaddrop.triage.anomaly import AnomalyDetector
from deaddrop.triage.scorer import TriageScorer


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


class TestAnomalyDetector:
    def test_no_entries_no_anomalies(self, case_mgr):
        """Empty timeline produces no anomalies."""
        c = case_mgr.create_case("Empty")
        detector = AnomalyDetector(case_mgr)
        result = detector.detect(c.id)
        assert result == []

    def test_temporal_burst(self, case_mgr):
        """Many events in one hour with few in other hours triggers burst detection."""
        c = case_mgr.create_case("Burst")
        # 30 events in one hour (clear outlier)
        for i in range(30):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-15T10:{i % 60:02d}:00", f"Event {i}", "info")
        # 1 event in each of 6 other hours (low activity baseline)
        for h in range(12, 18):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-15T{h:02d}:00:00", f"Quiet {h}")

        detector = AnomalyDetector(case_mgr)
        anomalies = detector.detect(c.id)
        burst = [a for a in anomalies if a["type"] == "temporal_burst"]
        assert len(burst) >= 1
        assert burst[0]["event_count"] == 30

    def test_severity_anomaly_high_ratio(self, case_mgr):
        """High ratio of high/critical events triggers severity anomaly."""
        c = case_mgr.create_case("High Severity")
        # 5 critical, 5 high, 5 medium = 50% high/critical
        for i in range(5):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-15T0{i}:00:00", f"Critical {i}", "critical")
        for i in range(5):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-16T0{i}:00:00", f"High {i}", "high")
        for i in range(5):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-17T0{i}:00:00", f"Medium {i}", "medium")

        detector = AnomalyDetector(case_mgr)
        anomalies = detector.detect(c.id)
        sev_anomalies = [a for a in anomalies if a["type"] in ("severity_distribution", "critical_events")]
        assert len(sev_anomalies) >= 1

    def test_source_dominance(self, case_mgr):
        """Single source dominating events triggers anomaly."""
        c = case_mgr.create_case("Source Dominance")
        # 60 events from one source, 5 from another
        for i in range(60):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-15T{i:02d}:00:00", f"Event {i}")
        for i in range(5):
            case_mgr.add_timeline_entry(c.id, "filesystem", f"2026-01-15T{i:02d}:30:00", f"FS {i}")

        detector = AnomalyDetector(case_mgr)
        anomalies = detector.detect(c.id)
        source_anomalies = [a for a in anomalies if a["type"] == "source_dominance"]
        assert len(source_anomalies) >= 1
        assert source_anomalies[0]["source"] == "events"


class TestTriageScorer:
    def test_score_empty_case(self, case_mgr):
        """Empty case gets minimal risk score."""
        c = case_mgr.create_case("Empty")
        scorer = TriageScorer(case_mgr)
        result = scorer.score(c.id)
        assert result["anomalies"] == 0
        assert result["risk_score"] == 0
        assert result["risk_level"] == "MINIMAL"

    def test_score_with_critical_events(self, case_mgr):
        """Case with many critical events gets high risk score."""
        c = case_mgr.create_case("Dangerous")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1024, "sha", "md5", "RAW")
        for i in range(10):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-15T0{i}:00:00", f"Critical {i}", "critical")

        scorer = TriageScorer(case_mgr)
        result = scorer.score(c.id)
        assert result["risk_score"] > 0
        assert result["critical"] > 0

    def test_risk_level_mapping(self, case_mgr):
        """Risk levels map correctly from scores."""
        assert TriageScorer._risk_level(80) == "CRITICAL"
        assert TriageScorer._risk_level(60) == "HIGH"
        assert TriageScorer._risk_level(30) == "MEDIUM"
        assert TriageScorer._risk_level(15) == "LOW"
        assert TriageScorer._risk_level(5) == "MINIMAL"

    def test_score_stores_artifacts(self, case_mgr):
        """Triage scoring stores anomaly artifacts in the case."""
        c = case_mgr.create_case("Artifact Check")
        # Add enough events to trigger anomalies
        for i in range(20):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-15T10:{i:02d}:00", f"Event {i}", "high")

        scorer = TriageScorer(case_mgr)
        result = scorer.score(c.id)
        if result["anomalies"] > 0:
            artifacts = case_mgr.list_artifacts(c.id, source="triage")
            assert len(artifacts) > 0
