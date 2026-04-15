"""Timeline Summary Plugin — Statistical overview of case timeline."""

from deaddrop.core.case import CaseManager
from deaddrop.core.config import Config


def run(case_id: str, **kwargs) -> dict:
    """Generate timeline statistics."""
    config = Config.load()
    mgr = CaseManager(config.db_path)
    timeline = mgr.get_timeline(case_id)

    severity_counts = {}
    source_counts = {}
    for entry in timeline:
        sev = entry.get("severity", "info")
        src = entry.get("source", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        source_counts[src] = source_counts.get(src, 0) + 1

    timestamps = [e["timestamp"] for e in timeline if e.get("timestamp")]
    time_range = {}
    if timestamps:
        time_range = {"earliest": min(timestamps), "latest": max(timestamps)}

    mgr.close()
    return {
        "total_entries": len(timeline),
        "severity_distribution": severity_counts,
        "source_distribution": source_counts,
        "time_range": time_range,
    }