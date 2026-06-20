"""YARA scanner — scan evidence with YARA rules."""

import uuid
from datetime import UTC, datetime
from pathlib import Path

from deaddrop.core.case import CaseManager

# Built-in YARA rules for common forensic indicators
BUILTIN_RULES = {
    "eicar": '''
rule EICAR_Test {
    meta:
        description = "EICAR test file detection"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}''',
    "suspicious_powershell": '''
rule Suspicious_PowerShell {
    meta:
        description = "Suspicious PowerShell command patterns"
        severity = "high"
    strings:
        $ps1 = "-EncodedCommand" nocase
        $ps2 = "-ExecutionPolicy Bypass" nocase
        $ps3 = "Invoke-Expression" nocase
        $ps4 = "IEX" nocase
        $ps5 = "DownloadString" nocase
        $ps6 = "FromBase64String" nocase
    condition:
        2 of ($ps1, $ps2, $ps3, $ps4, $ps5, $ps6)
}''',
    "suspicious_registry": '''
rule Suspicious_Registry_Modification {
    meta:
        description = "Registry persistence mechanisms"
        severity = "high"
    strings:
        $run1 = "CurrentVersion\\\\Run" nocase
        $run2 = "CurrentVersion\\\\RunOnce" nocase
        $svc1 = "CurrentControlSet\\\\Services" nocase
        $task = "Schedule\\\\TaskCache" nocase
    condition:
        any of them
}''',
    "credential_access": '''
rule Credential_Access {
    meta:
        description = "Credential access tool indicators"
        severity = "critical"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa" nocase
        $m3 = "lsadump" nocase
        $m4 = "kerberos" nocase wide
        $m5 = "procdump" nocase
    condition:
        2 of them
}''',
    "network_tool": '''
rule Network_Tool_Usage {
    meta:
        description = "Network reconnaissance tools"
        severity = "medium"
    strings:
        $n1 = "nmap" nocase
        $n2 = "netcat" nocase
        $n3 = "nc.exe" nocase
        $n4 = "wireshark" nocase
        $n5 = "tcpdump" nocase
    condition:
        any of them
}''',
    "exfiltration": '''
rule Data_Exfiltration {
    meta:
        description = "Data exfiltration indicators"
        severity = "high"
    strings:
        $e1 = "curl" nocase
        $e2 = "wget" nocase
        $e3 = "bitsadmin" nocase
        $e4 = "certutil -urlcache" nocase
        $e5 = "UploadFile" nocase
    condition:
        2 of them
}''',
    "ransomware": '''
rule Ransomware_Indicators {
    meta:
        description = "Ransomware indicators"
        severity = "critical"
    strings:
        $r1 = ".encrypted" nocase
        $r2 = "DECRYPT_INSTRUCTIONS" nocase
        $r3 = "vssadmin delete shadows" nocase
        $r4 = "wbadmin delete catalog" nocase
        $r5 = "bcdedit /set recoveryenabled" nocase
    condition:
        2 of them
}''',
    "rootkit": '''
rule Rootkit_Indicators {
    meta:
        description = "Rootkit indicators"
        severity = "critical"
    strings:
        $rk1 = "DKOM" nocase
        $rk2 = "SSDT" nocase
        $rk3 = "IRP hook" nocase
        $rk4 = "inline hook" nocase
        $rk5 = "driver object" nocase
    condition:
        2 of them
}''',
}


class YARAScanner:
    """Scan evidence files with YARA rules."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def scan(self, case_id: str, rules_path: str) -> dict:
        """Scan all evidence in a case with YARA rules from a file/directory."""
        rules = self._load_rules(rules_path)
        return self._execute_scan(case_id, rules)

    def scan_pack(self, case_id: str, pack_name: str) -> dict:
        """Scan using a pre-built hunt pack."""
        pack_path = Path(__file__).parent / "packs" / f"{pack_name}.yaml"
        if not pack_path.exists():
            return {"hits": 0, "error": f"Hunt pack '{pack_name}' not found"}

        import yaml
        pack = yaml.safe_load(pack_path.read_text())
        rules_str = pack.get("rules", "")
        if not rules_str:
            return {"hits": 0, "error": "No rules in hunt pack"}

        return self._execute_scan(case_id, {"pack": rules_str})

    def scan_builtin(self, case_id: str) -> dict:
        """Scan with built-in YARA rules."""
        return self._execute_scan(case_id, BUILTIN_RULES)

    def _execute_scan(self, case_id: str, rules: dict[str, str]) -> dict:
        """Execute YARA scan across all evidence in a case."""
        try:
            import yara
        except ImportError:
            return {"hits": 0, "error": "yara-python not installed. Run: pip install yara-python"}

        # Compile rules
        compiled_rules = {}
        for name, rule_source in rules.items():
            try:
                compiled = yara.compile(source=rule_source)
                compiled_rules[name] = compiled
            except yara.Error:
                continue

        # Get evidence files
        evidence_list = self.mgr.list_evidence(case_id)
        total_hits = 0

        for ev in evidence_list:
            ev_path = Path(ev["path"])
            if not ev_path.exists():
                continue

            # For disk images, scan in chunks (can't YARA-scan binary images efficiently)
            # For memory dumps and other files, scan directly
            try:
                if ev["type"] == "memory" or ev_path.stat().st_size < 500 * 1024 * 1024:
                    for _rule_name, compiled in compiled_rules.items():
                        matches = compiled.match(str(ev_path))
                        for match in matches:
                            severity = "medium"
                            # Try to extract severity from rule metadata
                            if match.meta and "severity" in match.meta:
                                severity = match.meta["severity"]

                            result_id = str(uuid.uuid4())[:12]
                            self.mgr.add_hunt_result(
                                case_id=case_id,
                                result_id=result_id,
                                rule_name=match.rule,
                                rule_type="yara",
                                severity=severity,
                                evidence_id=ev["id"],
                                match_data=str(match.strings[:5]) if match.strings else "",
                            )
                            total_hits += 1

                            # Also add as artifact
                            self.mgr.add_artifact(
                                case_id=case_id,
                                evidence_id=ev["id"],
                                source="hunt",
                                category="yara_match",
                                timestamp=datetime.now(UTC).isoformat(),
                                description=f"YARA match: {match.rule} in {ev['filename']}",
                                severity=severity,
                                data=str({"rule": match.rule, "strings": [str(s) for s in match.strings[:5]]}),
                            )
            except (OSError, PermissionError):
                continue

        return {"hits": total_hits}

    def _load_rules(self, rules_path: str) -> dict[str, str]:
        """Load YARA rules from a file or directory."""
        path = Path(rules_path)
        rules = {}

        if path.is_file():
            rules[path.stem] = path.read_text()
        elif path.is_dir():
            for yara_file in path.glob("*.yar"):
                rules[yara_file.stem] = yara_file.read_text()
            for yara_file in path.glob("*.yara"):
                rules[yara_file.stem] = yara_file.read_text()

        return rules
