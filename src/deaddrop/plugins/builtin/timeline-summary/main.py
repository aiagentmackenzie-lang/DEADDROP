"""Timeline Summary Plugin — Statistical overview of case timeline."""

from deaddrop.core.case import CaseManager


def run(case_id: str, case_manager: CaseManager | None = None, **kwargs) -> dict:
    """Generate timeline statistics.

    Accepts an optional case_manager to reuse the existing connection.
    Falls back to Config defaults when not provided (legacy mode).
    """
    if case_manager is None:
        from deaddrop.core.config import Config
        config = Config.load()
        case_manager = CaseManager(config.db_path)

    timeline = case_manager.get_timeline(case_id)

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

    return {
        "total_entries": len(timeline),
        "severity_distribution": severity_counts,
        "source_distribution": source_counts,
        "time_range": time_range,
    }