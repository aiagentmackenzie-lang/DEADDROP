"""YARA scanner — scan evidence with YARA rules."""

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from deaddrop.core.case import CaseManager

# Built-in YARA rules for common forensic indicators
BUILTIN_RULES = {
    "eicar": '''
rule EICAR_Test {
    meta:
        description = "EICAR test file detection"
        severity = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
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
            try:
                total_hits += self._scan_evidence(
                    case_id, ev, ev_path, compiled_rules
                )
            except (OSError, PermissionError):
                continue

        return {"hits": total_hits}

    # Files larger than this are scanned in CHUNK-size windows written to a
    # temp file (yara.match mmaps the path; chunking bounds memory + lets the
    # scan make progress on multi-GB disk images instead of silently skipping
    # them — SB-7). yara-python has no per-call timeout, so chunking also bounds
    # the worst-case time per evidence item.
    MAX_DIRECT_SCAN_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB
    SCAN_CHUNK = 512 * 1024 * 1024  # 512 MiB windows, 16 MiB overlap
    SCAN_OVERLAP = 16 * 1024 * 1024

    def _scan_evidence(
        self, case_id: str, ev: dict, ev_path: Path,
        compiled_rules: dict[str, Any],
    ) -> int:
        """Scan one evidence file, chunking if it exceeds MAX_DIRECT_SCAN_SIZE."""
        size = ev_path.stat().st_size
        if size <= self.MAX_DIRECT_SCAN_SIZE:
            return self._scan_file(case_id, ev, str(ev_path), compiled_rules, 0)

        # Chunked scan for large images: write overlapping windows to a temp
        # file and scan each. The overlap catches signatures straddling a
        # window boundary. Hits are deduplicated by (rule, absolute_offset).
        import tempfile
        seen: set[tuple[str, int]] = set()
        hits = 0
        with tempfile.TemporaryDirectory(prefix="deaddrop_yara_") as tmp:
            tmpfile = Path(tmp) / "chunk.bin"
            offset = 0
            with open(ev_path, "rb") as src:
                while offset < size:
                    src.seek(offset)
                    window = min(self.SCAN_CHUNK, size - offset)
                    data = src.read(window)
                    if not data:
                        break
                    tmpfile.write_bytes(data)
                    chunk_hits = self._scan_file(
                        case_id, ev, str(tmpfile), compiled_rules, offset,
                        seen=seen,
                    )
                    hits += chunk_hits
                    if window < self.SCAN_CHUNK:
                        break  # last partial window
                    offset += self.SCAN_CHUNK - self.SCAN_OVERLAP
        return hits

    def _scan_file(
        self, case_id: str, ev: dict, file_path: str,
        compiled_rules: dict[str, Any], base_offset: int,
        seen: set[tuple[str, int]] | None = None,
    ) -> int:
        """Scan one file with every compiled rule; record + dedupe hits.

        `base_offset` is added to each match's offset to map chunk hits back to
        their absolute position in the original evidence file. `seen` dedupes
        across overlapping chunk windows.
        """
        hits = 0
        for _rule_name, compiled in compiled_rules.items():
            matches = compiled.match(file_path)
            for match in matches:
                severity = "medium"
                if match.meta and "severity" in match.meta:
                    severity = match.meta["severity"]
                # Absolute offset of the first matched string (if available).
                abs_off = base_offset
                try:
                    if match.strings:
                        # yara-python 4.x: match.strings is list of (off, ident, data)
                        first = match.strings[0]
                        abs_off = base_offset + (first[0] if isinstance(first, tuple) else 0)
                except (IndexError, TypeError):
                    pass
                if seen is not None:
                    key = (match.rule, abs_off)
                    if key in seen:
                        continue
                    seen.add(key)

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
                hits += 1
                self.mgr.add_artifact(
                    case_id=case_id,
                    evidence_id=ev["id"],
                    source="hunt",
                    category="yara_match",
                    timestamp=datetime.now(UTC).isoformat(),
                    description=f"YARA match: {match.rule} in {ev['filename']} @0x{abs_off:x}",
                    severity=severity,
                    data=str({"rule": match.rule, "offset": abs_off,
                              "strings": [str(s) for s in match.strings[:5]]}),
                )
        return hits

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
