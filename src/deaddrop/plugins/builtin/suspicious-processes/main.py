"""Suspicious Processes Plugin — Flag known malicious/suspicious process names."""

from deaddrop.core.case import CaseManager

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe": "critical",
    "procdump.exe": "high",
    "psexec.exe": "high",
    "nc.exe": "high",
    "ncat.exe": "high",
    "certutil.exe": "high",
    "bitsadmin.exe": "high",
    "mshta.exe": "high",
    "wmic.exe": "medium",
    "vssadmin.exe": "high",
    "wbadmin.exe": "high",
    "bcdedit.exe": "medium",
    "cipher.exe": "medium",
    "schtasks.exe": "medium",
    "at.exe": "medium",
    "reg.exe": "medium",
    "crackmapexec.exe": "critical",
    "bloodhound.exe": "critical",
    "sharphound.exe": "critical",
    "rubeus.exe": "critical",
    "cobaltstrike.exe": "critical",
    "beacon.exe": "critical",
}


def run(case_id: str, case_manager: CaseManager | None = None, **kwargs) -> dict:
    """Check memory artifacts for suspicious processes.

    Accepts an optional case_manager to reuse the existing connection.
    Falls back to Config defaults when not provided (legacy mode).
    """
    if case_manager is None:
        from deaddrop.core.config import Config
        config = Config.load()
        case_manager = CaseManager(config.db_path)

    artifacts = case_manager.list_artifacts(case_id, source="memory")

    findings = {"suspicious": [], "total_checked": 0}

    for artifact in artifacts:
        findings["total_checked"] += 1
        desc = artifact.get("description", "").lower()
        data = str(artifact.get("data", "")).lower()

        for proc, severity in SUSPICIOUS_PROCESSES.items():
            if proc.lower() in desc or proc.lower() in data:
                findings["suspicious"].append({
                    "process": proc,
                    "severity": severity,
                    "artifact_id": artifact.get("id", ""),
                })

    return findings
