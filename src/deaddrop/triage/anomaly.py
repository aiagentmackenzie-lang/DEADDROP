"""Anomaly detection — statistical outlier detection on timeline events."""

import math
from collections import Counter

from deaddrop.core.case import CaseManager


class AnomalyDetector:
    """Detect anomalous patterns in forensic timeline data."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def detect(self, case_id: str) -> list[dict]:
        """Run anomaly detection on case timeline."""
        entries = self.mgr.get_timeline(case_id)
        if not entries:
            return []

        anomalies = []

        # 1. Temporal anomaly: bursts of activity
        temporal_anomalies = self._detect_temporal_bursts(entries)
        anomalies.extend(temporal_anomalies)

        # 2. Severity anomaly: unexpected severity distribution
        severity_anomalies = self._detect_severity_anomalies(entries)
        anomalies.extend(severity_anomalies)

        # 3. Source anomaly: unusual source patterns
        source_anomalies = self._detect_source_anomalies(entries)
        anomalies.extend(source_anomalies)

        # 4. Pattern anomaly: known attack pattern sequences
        pattern_anomalies = self._detect_attack_patterns(entries)
        anomalies.extend(pattern_anomalies)

        return anomalies

    def _detect_temporal_bursts(self, entries: list[dict]) -> list[dict]:
        """Detect bursts of activity (many events in short time)."""
        anomalies: list[dict] = []
        if len(entries) < 5:
            return anomalies

        # Bucket events by hour
        hour_counts: Counter[str] = Counter()
        for entry in entries:
            ts = entry.get("timestamp", "")
            if ts:
                hour_key = ts[:13]  # ISO format hour
                hour_counts[hour_key] += 1

        if not hour_counts:
            return anomalies

        # Calculate mean and sample standard deviation (Bessel's correction: N-1)
        counts = list(hour_counts.values())
        mean = sum(counts) / len(counts)
        n = len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / (n - 1) if n > 1 else 0
        std = math.sqrt(variance) if variance > 0 else 0

        # Flag hours with > 2 standard deviations above mean
        threshold = mean + 2 * std if std > 0 else mean * 3

        for hour, count in hour_counts.items():
            if count > threshold and count > 5:
                anomalies.append({
                    "type": "temporal_burst",
                    "hour": hour,
                    "event_count": count,
                    "mean": round(mean, 2),
                    "threshold": round(threshold, 2),
                    "score": min(round((count - mean) / std, 2), 10.0) if std > 0 else 10.0,
                    "description": f"Temporal burst: {count} events in {hour} (mean: {mean:.1f})",
                    "severity": "high" if count > mean * 5 else "medium",
                })

        return anomalies

    def _detect_severity_anomalies(self, entries: list[dict]) -> list[dict]:
        """Detect unusual severity distributions."""
        anomalies = []
        severity_counts: Counter[str] = Counter()
        for entry in entries:
            sev = entry.get("severity", "info")
            severity_counts[sev] += 1

        total = len(entries)
        high_pct = (severity_counts.get("high", 0) + severity_counts.get("critical", 0)) / total * 100

        if high_pct > 30:
            anomalies.append({
                "type": "severity_distribution",
                "high_critical_pct": round(high_pct, 1),
                "score": round(high_pct / 10, 2),
                "description": f"High severity ratio: {high_pct:.1f}% of events are high/critical",
                "severity": "high" if high_pct > 50 else "medium",
            })

        if severity_counts.get("critical", 0) > 3:
            anomalies.append({
                "type": "critical_events",
                "critical_count": severity_counts["critical"],
                "score": round(severity_counts["critical"] * 2, 2),
                "description": f"{severity_counts['critical']} critical severity events detected",
                "severity": "critical",
            })

        return anomalies

    def _detect_source_anomalies(self, entries: list[dict]) -> list[dict]:
        """Detect unusual source patterns."""
        anomalies = []
        source_counts: Counter[str] = Counter()
        for entry in entries:
            source_counts[entry.get("source", "unknown")] += 1

        # Flag sources with very high event counts
        total = len(entries)
        for source, count in source_counts.items():
            pct = count / total * 100
            if pct > 70 and total > 50:
                anomalies.append({
                    "type": "source_dominance",
                    "source": source,
                    "count": count,
                    "pct": round(pct, 1),
                    "score": round(pct / 20, 2),
                    "description": f"Source dominance: {source} accounts for {pct:.1f}% of events",
                    "severity": "medium",
                })

        return anomalies

    def _detect_attack_patterns(self, entries: list[dict]) -> list[dict]:
        """Detect known attack pattern sequences in timeline.

        Checks for temporal ordering — earlier-phase sources must appear
        before later-phase sources to flag a pattern.
        """
        anomalies: list[dict] = []

        # Build ordered source sequence from sorted timeline
        sources = [e.get("source", "") for e in entries if e.get("source")]

        if len(sources) < 3:
            return anomalies

        # Pattern: earlier sources must appear before later ones
        # (reconnaissance → exploitation → persistence → exfiltration)
        patterns = {
            "recon_to_exploit": {
                "required": ["filesystem", "events"],
                "description": "Reconnaissance followed by exploitation",
            },
            "persistence_after_exploit": {
                "required": ["events", "registry"],
                "description": "Exploitation followed by persistence",
            },
            "exfil_after_access": {
                "required": ["memory", "hunt"],
                "description": "Access followed by data hunting",
            },
        }

        for pattern_name, spec in patterns.items():
            required = spec["required"]
            # Find first occurrence index of each required source
            positions = []
            for source in required:
                try:
                    idx = sources.index(source)
                    positions.append(idx)
                except ValueError:
                    # Source not present at all
                    break

            # All sources found AND in temporal order
            if len(positions) == len(required) and positions == sorted(positions):
                anomalies.append({
                    "type": "attack_pattern",
                    "pattern": pattern_name,
                    "score": 7.0,
                    "description": f"Potential attack pattern: {spec['description']}",
                    "severity": "high",
                })

        return anomalies
