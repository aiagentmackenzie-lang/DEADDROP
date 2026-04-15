"""Triage scorer — aggregate anomaly scores and prioritize findings."""

import uuid
from datetime import datetime, timezone

from deaddrop.core.case import CaseManager
from deaddrop.triage.anomaly import AnomalyDetector


class TriageScorer:
    """Score and prioritize forensic findings for triage."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager
        self.detector = AnomalyDetector(case_manager)

    def score(self, case_id: str) -> dict:
        """Run full triage scoring on a case."""
        anomalies = self.detector.detect(case_id)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for anomaly in anomalies:
            sev = anomaly.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Calculate overall risk score (0-100)
        risk_score = self._calculate_risk_score(anomalies, severity_counts)

        # Store anomalies as artifacts
        for anomaly in anomalies:
            self.mgr.add_artifact(
                case_id=case_id,
                evidence_id="",
                source="triage",
                category=anomaly.get("type", "anomaly"),
                timestamp=datetime.now(timezone.utc).isoformat(),
                description=anomaly.get("description", ""),
                severity=anomaly.get("severity", "info"),
                data=str(anomaly),
                artifact_id=str(uuid.uuid4())[:8],
            )

        return {
            "anomalies": len(anomalies),
            "high": severity_counts["high"] + severity_counts["critical"],
            "critical": severity_counts["critical"],
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "anomaly_details": anomalies[:20],  # Top 20
        }

    def _calculate_risk_score(self, anomalies: list[dict], severity_counts: dict) -> float:
        """Calculate overall risk score from 0-100."""
        weights = {"critical": 25, "high": 10, "medium": 3, "low": 1, "info": 0}
        raw_score = sum(
            severity_counts.get(sev, 0) * weight
            for sev, weight in weights.items()
        )

        # Add anomaly scores
        anomaly_score = sum(a.get("score", 0) for a in anomalies)

        # Normalize to 0-100
        total = raw_score + anomaly_score * 2
        return min(round(total, 1), 100.0)

    @staticmethod
    def _risk_level(score: float) -> str:
        """Convert risk score to level."""
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        if score >= 10:
            return "LOW"
        return "MINIMAL"