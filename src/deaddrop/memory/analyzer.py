"""Memory analyzer — extract and correlate memory artifacts."""


from typing import ClassVar

from deaddrop.core.case import CaseManager
from deaddrop.memory.volatility import VolatilityWrapper


class MemoryAnalyzer:
    """High-level memory analysis — correlate artifacts from multiple plugins."""

    SUSPICIOUS_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "injection": ["malfind", "vadyarascan"],
        "persistence": ["registry.printkey", "pslist"],
        "lateral_movement": ["netscan", "netstat"],
        "credential_access": ["malfind", "lsadump"],
        "defense_evasion": ["ssdt", "callbacks", "malfind"],
    }

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager
        self.wrapper = VolatilityWrapper(case_manager)

    def full_analysis(self, case_id: str, evidence_id: str | None = None) -> dict:
        """Run comprehensive memory analysis across key plugins."""
        key_plugins = [
            "windows.info",
            "windows.pslist",
            "windows.psscan",
            "windows.netscan",
            "windows.malfind",
            "windows.dlllist",
            "windows.handles",
        ]

        results = {"plugins_run": 0, "total_findings": 0, "high_severity": 0}

        for plugin in key_plugins:
            result = self.wrapper.run_plugin(case_id, evidence_id, plugin)
            results["plugins_run"] += 1
            results["total_findings"] += result.get("findings_count", 0)

        # Count high severity artifacts
        artifacts = self.mgr.list_artifacts(case_id, source="memory")
        results["high_severity"] = len([a for a in artifacts if a.get("severity") in ("high", "critical")])

        return results
