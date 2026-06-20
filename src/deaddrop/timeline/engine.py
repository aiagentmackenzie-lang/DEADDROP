"""Timeline engine — merge, sort, and filter forensic timeline entries."""


from deaddrop.core.case import CaseManager


class TimelineEngine:
    """Generate super-timelines from multiple forensic sources."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def generate(self, case_id: str) -> dict:
        """Generate a unified timeline from all artifacts in a case."""
        entries = self.mgr.get_timeline(case_id)

        # Build a set of artifact IDs already in the timeline for O(1) lookup
        existing_artifact_ids = {
            e["artifact_id"]
            for e in entries
            if e.get("artifact_id")
        }

        # Add entries from artifacts that have timestamps but aren't yet in timeline
        artifacts = self.mgr.list_artifacts(case_id)
        for artifact in artifacts:
            if (
                artifact.get("timestamp")
                and artifact["id"] not in existing_artifact_ids
            ):
                self.mgr.add_timeline_entry(
                    case_id=case_id,
                    source=artifact["source"],
                    timestamp=artifact["timestamp"],
                    description=artifact["description"],
                    severity=artifact.get("severity", "info"),
                    evidence_id=artifact.get("evidence_id") or None,
                    artifact_id=artifact["id"],
                )
                existing_artifact_ids.add(artifact["id"])

        # Re-fetch after additions
        entries = self.mgr.get_timeline(case_id)

        # Count by source
        sources: dict[str, int] = {}
        for entry in entries:
            src = entry.get("source", "unknown")
            sources[src] = sources.get(src, 0) + 1

        return {
            "total_entries": len(entries),
            "sources": list(sources.keys()),
            "source_counts": sources,
        }

    def filter_entries(self, case_id: str, from_ts: str | None = None,
                       to_ts: str | None = None, source: str | None = None) -> list[dict]:
        """Filter timeline entries by time range and source."""
        entries = self.mgr.get_timeline(case_id, from_ts or "", to_ts or "")

        if source:
            entries = [e for e in entries if e.get("source") == source]

        return entries

    def get_stats(self, case_id: str) -> dict:
        """Get timeline statistics."""
        entries = self.mgr.get_timeline(case_id)

        severity_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        for entry in entries:
            sev = entry.get("severity", "info")
            src = entry.get("source", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            source_counts[src] = source_counts.get(src, 0) + 1

        # Time range
        timestamps = [e["timestamp"] for e in entries if e.get("timestamp")]
        time_range = {}
        if timestamps:
            time_range = {"earliest": min(timestamps), "latest": max(timestamps)}

        return {
            "total": len(entries),
            "severity_counts": severity_counts,
            "source_counts": source_counts,
            "time_range": time_range,
        }
