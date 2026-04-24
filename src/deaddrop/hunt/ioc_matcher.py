"""IOC matcher — match indicators of compromise against evidence."""

import uuid
import re
import json
from pathlib import Path

from deaddrop.core.case import CaseManager


# IOC pattern matchers
IOC_PATTERNS = {
    "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "url": re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "cve": re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
}


class IOCMatcher:
    """Match indicators of compromise against evidence files."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def match(self, case_id: str, ioc_path: str) -> dict:
        """Match IOCs from a JSON file against case evidence."""
        path = Path(ioc_path)
        if not path.exists():
            return {"hits": 0, "error": f"IOC file not found: {ioc_path}"}

        try:
            ioc_data = json.loads(path.read_text())
        except json.JSONDecodeError:
            return {"hits": 0, "error": "Invalid JSON in IOC file"}

        iocs = self._parse_iocs(ioc_data)
        return self._match_iocs(case_id, iocs)

    def match_patterns(self, case_id: str) -> dict:
        """Auto-detect IOCs in evidence using regex patterns."""
        iocs = {}
        evidence_list = self.mgr.list_evidence(case_id)

        for ev in evidence_list:
            ev_path = Path(ev["path"])
            if not ev_path.exists():
                continue
            try:
                # Read file content for pattern matching (limit to first 100MB)
                content = ev_path.read_bytes()[:100 * 1024 * 1024]
                text_content = content.decode("utf-8", errors="replace")

                for pattern_name, pattern in IOC_PATTERNS.items():
                    matches = pattern.findall(text_content)
                    if matches:
                        # Deduplicate
                        unique = list(set(matches))[:100]
                        iocs[pattern_name] = iocs.get(pattern_name, []) + unique
            except (OSError, MemoryError):
                continue

        return self._match_iocs(case_id, iocs)

    def _match_iocs(self, case_id: str, iocs: dict) -> dict:
        """Match collected IOCs against evidence and store results."""
        total_hits = 0

        for ioc_type, values in iocs.items():
            for value in values[:1000]:  # Cap per type
                severity = self._assess_severity(ioc_type, value)
                result_id = str(uuid.uuid4())[:8]
                self.mgr.add_hunt_result(
                    case_id=case_id,
                    result_id=result_id,
                    rule_name=f"{ioc_type}:{value}",
                    rule_type="ioc",
                    severity=severity,
                    match_data=value,
                )
                total_hits += 1

        return {"hits": total_hits}

    def _parse_iocs(self, data: dict | list) -> dict:
        """Parse IOC data from various formats."""
        iocs = {}

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ioc_type = item.get("type", "unknown")
                    ioc_value = item.get("value", item.get("indicator", ""))
                    if ioc_value:
                        iocs.setdefault(ioc_type, []).append(ioc_value)
                elif isinstance(item, str):
                    # Auto-detect type
                    for pattern_name, pattern in IOC_PATTERNS.items():
                        if pattern.match(item):
                            iocs.setdefault(pattern_name, []).append(item)
                            break
                    else:
                        iocs.setdefault("unknown", []).append(item)

        elif isinstance(data, dict):
            # Support STIX-like format
            if "objects" in data:
                for obj in data["objects"]:
                    if obj.get("type") == "indicator":
                        pattern = obj.get("pattern", "")
                        ioc_type = obj.get("indicator_types", ["unknown"])[0]
                        iocs.setdefault(ioc_type, []).append(pattern)
            else:
                for key, values in data.items():
                    if isinstance(values, list):
                        iocs[key] = values
                    else:
                        iocs.setdefault("custom", []).append(str(values))

        return iocs

    @staticmethod
    def _assess_severity(ioc_type: str, value: str) -> str:
        """Assess severity based on IOC type and value."""
        high_severity_types = {"sha256", "sha1", "md5", "cve"}
        if ioc_type in high_severity_types:
            return "high"

        # Check for suspicious patterns
        suspicious_domains = {".ru", ".cn", ".ir", ".kp", ".onion"}
        if ioc_type == "domain":
            for tld in suspicious_domains:
                if value.endswith(tld):
                    return "high"
            return "medium"

        if ioc_type == "ipv4":
            # Known C2 ranges (simplified)
            private_ranges = ("10.", "172.16.", "192.168.")
            if value.startswith(private_ranges):
                return "info"
            return "medium"

        return "medium"