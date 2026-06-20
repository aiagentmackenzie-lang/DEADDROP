r"""Windows event log analyzer — parse EVTX files for security events.

Integrates python-evtx (EVTX.Evtx) to actually parse records — the prior
implementation only checked the \`ElfFile\` magic and returned a single metadata
row, so \`deaddrop analyze events\` produced zero security events on any real
log (SB-6). This parser extracts EventID from each record's XML, classifies it
against SECURITY_EVENTS, and emits artifacts + timeline entries.
"""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path

from deaddrop.core.case import CaseManager

log = logging.getLogger(__name__)

# Critical security event IDs (unchanged from v1.0 — verified 28 entries)
SECURITY_EVENTS: dict[str, dict[str, str]] = {
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

# Extract <EventID>123</EventID> from EVTX record XML (tolerant of namespaces)
_EVENTID_RE = re.compile(r"<EventID[^>]*>(\d+)</EventID>", re.IGNORECASE)
_TIME_RE = re.compile(
    r"<TimeCreated\s+SystemTime=['\"]([^'\"]+)['\"]", re.IGNORECASE
)
_CHANNEL_RE = re.compile(r"<Channel>([^<]+)</Channel>", re.IGNORECASE)
_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>", re.IGNORECASE)


class EventLogAnalyzer:
    """Analyze Windows event logs (EVTX) for security events."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def analyze(self, case_id: str, evidence_id: str | None = None, source: str | None = None) -> dict:
        """Analyze EVTX files referenced by a case's disk evidence."""
        evidence_list = self.mgr.list_evidence(case_id)
        disk_evidence = [e for e in evidence_list if e["type"] == "disk"]
        if evidence_id:
            disk_evidence = [e for e in disk_evidence if e["id"] == evidence_id]

        events_parsed = 0
        security_events = 0
        high_severity = 0

        for ev in disk_evidence:
            for artifact in self._extract_event_artifacts(ev, source):
                self.mgr.add_artifact(
                    case_id=case_id,
                    evidence_id=ev["id"],
                    source="events",
                    category=artifact["category"],
                    timestamp=artifact.get("timestamp", ""),
                    description=artifact["description"],
                    severity=artifact["severity"],
                    data=str(artifact),
                    artifact_id=str(uuid.uuid4())[:12],
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

    def _extract_event_artifacts(self, evidence: dict, source_filter: str | None = None) -> list[dict]:
        """Parse every .evtx file found next to the evidence path.

        If the evidence path is a directory, scan for *.evtx; if it's a file
        with the right magic, parse it directly. Returns [] when python-evtx
        is unavailable or nothing parses.
        """
        import importlib.util
        if importlib.util.find_spec("Evtx") is None:
            log.warning("python-evtx not installed; EVTX parsing unavailable. "
                        "Install with: pip install python-evtx")
            return []

        path = Path(evidence["path"])
        evtx_files: list[Path] = []
        if path.is_dir():
            evtx_files = sorted(path.glob("*.evtx"))
        elif path.is_file() and self._looks_like_evtx(path):
            evtx_files = [path]

        artifacts: list[dict] = []
        for evtx in evtx_files:
            try:
                artifacts.extend(self._parse_evtx_file(evtx, source_filter))
            except Exception as e:
                log.warning("Failed to parse %s: %s", evtx, e)
        return artifacts

    @staticmethod
    def _looks_like_evtx(path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(8)[:8] == b"ElfFile\x00"
        except OSError:
            return False

    def _parse_evtx_file(self, evtx_path: Path, source_filter: str | None) -> list[dict]:
        """Parse one EVTX file with python-evtx, yielding classified artifacts."""
        from Evtx.Evtx import Evtx as EvtxParser

        out: list[dict] = []
        with EvtxParser(str(evtx_path)) as log_handle:
            for record in log_handle.records():
                try:
                    xml = record.xml()
                except Exception:
                    continue
                if not xml:
                    continue
                event_id = self._extract(xml, _EVENTID_RE)
                if not event_id:
                    continue
                if event_id not in SECURITY_EVENTS:
                    # Non-security event — record only if no source filter.
                    if source_filter:
                        continue
                    continue  # we only persist classified security events

                meta = SECURITY_EVENTS[event_id]
                channel = self._extract(xml, _CHANNEL_RE) or evtx_path.stem
                if source_filter and channel.lower() != source_filter.lower():
                    continue
                timestamp = self._extract(xml, _TIME_RE) or ""
                computer = self._extract(xml, _COMPUTER_RE) or ""
                desc = f"[{event_id}] {meta['name']} ({channel}"
                if computer:
                    desc += f"@{computer}"
                desc += ")"
                out.append({
                    "event_id": event_id,
                    "event_name": meta["name"],
                    "category": "security",
                    "description": desc,
                    "severity": meta["severity"],
                    "timestamp": timestamp,
                    "source": channel,
                    "file": str(evtx_path),
                })
        return out

    @staticmethod
    def _extract(xml: str, pattern: re.Pattern[str]) -> str | None:
        m = pattern.search(xml)
        return m.group(1) if m else None

    def parse_evtx(self, evtx_path: Path) -> list[dict]:
        """Parse a single EVTX file and return its security events (legacy API)."""
        import importlib.util
        if importlib.util.find_spec("Evtx") is None:
            return []
        if not evtx_path.exists() or not self._looks_like_evtx(evtx_path):
            return []
        return self._parse_evtx_file(evtx_path, source_filter=None)
