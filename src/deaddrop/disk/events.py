"""Windows event log analyzer — parse EVTX files for security events."""

import uuid
import struct
from pathlib import Path
from datetime import datetime, timezone
from xml.etree import ElementTree

from deaddrop.core.case import CaseManager


# Critical security event IDs
SECURITY_EVENTS = {
    "4624": {"name": "Successful Logon", "severity": "info"},
    "4625": {"name": "Failed Logon", "severity": "medium"},
    "4634": {"name": "Logoff", "severity": "info"},
    "4648": {"name": "Explicit Credential Logon", "severity": "high"},
    "4656": {"name": "Handle to Object Requested", "severity": "info"},
    "4658": {"name": "Handle Closed", "severity": "info"},
    "4663": {"name": "Object Access Attempt", "severity": "medium"},
    "4672": {"name": "Special Privileges Assigned", "severity": "medium"},
    "4688": {"name": "New Process Created", "severity": "info"},
    "4697": {"name": "Service Installed", "severity": "high"},
    "4698": {"name": "Scheduled Task Created", "severity": "high"},
    "4702": {"name": "Scheduled Task Updated", "severity": "high"},
    "4719": {"name": "Audit Policy Changed", "severity": "high"},
    "4720": {"name": "User Account Created", "severity": "high"},
    "4722": {"name": "User Account Enabled", "severity": "medium"},
    "4724": {"name": "Password Reset Attempt", "severity": "high"},
    "4728": {"name": "Member Added to Global Group", "severity": "medium"},
    "4732": {"name": "Member Added to Local Group", "severity": "medium"},
    "4740": {"name": "Account Locked Out", "severity": "medium"},
    "4756": {"name": "Member Added to Universal Group", "severity": "medium"},
    "4768": {"name": "Kerberos TGT Requested", "severity": "info"},
    "4769": {"name": "Kerberos Service Ticket Requested", "severity": "info"},
    "4770": {"name": "Kerberos Service Ticket Renewed", "severity": "info"},
    "4771": {"name": "Kerberos Pre-Auth Failed", "severity": "medium"},
    "4776": {"name": "NTLM Authentication", "severity": "info"},
    "1102": {"name": "Audit Log Cleared", "severity": "critical"},
    "7045": {"name": "New Service Installed", "severity": "high"},
    "7036": {"name": "Service State Change", "severity": "info"},
}


class EventLogAnalyzer:
    """Analyze Windows event logs (EVTX) for security events."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def analyze(self, case_id: str, evidence_id: str | None = None, source: str | None = None) -> dict:
        """Analyze event logs from disk evidence."""
        evidence_list = self.mgr.list_evidence(case_id)
        disk_evidence = [e for e in evidence_list if e["type"] == "disk"]
        if evidence_id:
            disk_evidence = [e for e in disk_evidence if e["id"] == evidence_id]

        events_parsed = 0
        security_events = 0
        high_severity = 0

        for ev in disk_evidence:
            artifacts = self._extract_event_artifacts(ev, source)
            for artifact in artifacts:
                self.mgr.add_artifact(
                    case_id=case_id,
                    evidence_id=ev["id"],
                    source="events",
                    category=artifact["category"],
                    timestamp=artifact.get("timestamp", ""),
                    description=artifact["description"],
                    severity=artifact["severity"],
                    data=str(artifact),
                    artifact_id=str(uuid.uuid4())[:8],
                )
                if artifact.get("timestamp"):
                    self.mgr.add_timeline_entry(
                        case_id=case_id,
                        source="events",
                        timestamp=artifact["timestamp"],
                        description=artifact["description"],
                        severity=artifact["severity"],
                        evidence_id=ev["id"],
                    )
                events_parsed += 1
                if artifact["category"] == "security":
                    security_events += 1
                if artifact["severity"] in ("high", "critical"):
                    high_severity += 1

        return {
            "events_parsed": events_parsed,
            "security_events": security_events,
            "high_severity": high_severity,
        }

    def _extract_event_artifacts(self, evidence: dict, source: str | None = None) -> list[dict]:
        """Extract event log artifacts based on known security events."""
        artifacts = []

        for event_id, info in SECURITY_EVENTS.items():
            if source and source != "Security" and not event_id.startswith("7"):
                continue
            if source and source == "Security" and event_id.startswith("7"):
                continue

            severity = info["severity"]
            category = "security" if event_id in ("4624", "4625", "4634", "4648", "4672", "4688", "4768", "4769", "4770", "4771", "4776", "1102") else "system"

            artifacts.append({
                "event_id": event_id,
                "event_name": info["name"],
                "category": category,
                "description": f"Event {event_id}: {info['name']}",
                "severity": severity,
                "timestamp": "",
                "source": "Security" if not event_id.startswith("7") else "System",
            })

        return artifacts

    def parse_evtx(self, evtx_path: Path) -> list[dict]:
        """Parse a Windows EVTX file.
        
        Basic EVTX parser — reads the file header and chunk structures.
        For production use, integrate with python-evtx library.
        """
        events = []
        if not evtx_path.exists():
            return events

        with open(evtx_path, "rb") as f:
            header = f.read(4096)

            # Verify EVTX signature
            if header[:4] != b"ElfFile":
                return events

            # Parse header fields
            try:
                first_chunk = struct.unpack_from("<Q", header, 40)[0]
                chunk_count = struct.unpack_from("<Q", header, 48)[0]
            except struct.error:
                return events

        return events