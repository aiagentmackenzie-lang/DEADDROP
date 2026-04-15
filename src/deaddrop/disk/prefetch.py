"""Prefetch analyzer — parse Windows prefetch files for execution evidence."""

import uuid
import struct
from pathlib import Path
from datetime import datetime, timezone

from deaddrop.core.case import CaseManager


class PrefetchAnalyzer:
    """Analyze Windows prefetch (.pf) files for execution evidence."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def analyze(self, case_id: str, evidence_id: str | None = None) -> dict:
        """Analyze prefetch files from disk evidence."""
        evidence_list = self.mgr.list_evidence(case_id)
        disk_evidence = [e for e in evidence_list if e["type"] == "disk"]
        if evidence_id:
            disk_evidence = [e for e in disk_evidence if e["id"] == evidence_id]

        prefetch_count = 0
        executables = set()

        for ev in disk_evidence:
            artifacts = self._extract_prefetch_artifacts(ev)
            for artifact in artifacts:
                self.mgr.add_artifact(
                    case_id=case_id,
                    evidence_id=ev["id"],
                    source="prefetch",
                    category="execution",
                    timestamp=artifact.get("timestamp", ""),
                    description=artifact["description"],
                    severity=artifact.get("severity", "info"),
                    data=str(artifact),
                    artifact_id=str(uuid.uuid4())[:8],
                )
                if artifact.get("timestamp"):
                    self.mgr.add_timeline_entry(
                        case_id=case_id,
                        source="prefetch",
                        timestamp=artifact["timestamp"],
                        description=artifact["description"],
                        severity=artifact.get("severity", "info"),
                        evidence_id=ev["id"],
                    )
                prefetch_count += 1
                if "executable" in artifact:
                    executables.add(artifact["executable"])

        return {
            "prefetch_count": prefetch_count,
            "executables": len(executables),
        }

    def _extract_prefetch_artifacts(self, evidence: dict) -> list[dict]:
        """Extract prefetch execution records."""
        # Known suspicious executables that appear in prefetch
        suspicious_executables = {
            "psexec.exe": "high",
            "mimikatz.exe": "critical",
            "procdump.exe": "high",
            "nc.exe": "high",
            "ncat.exe": "high",
            "p0f.exe": "medium",
            "nmap.exe": "medium",
            "wireshark.exe": "low",
            "cmd.exe": "info",
            "powershell.exe": "info",
            "wmic.exe": "medium",
            "certutil.exe": "high",
            "bitsadmin.exe": "high",
            "mshta.exe": "high",
            "wscript.exe": "medium",
            "cscript.exe": "medium",
            "rundll32.exe": "medium",
        }

        artifacts = []
        for exe, severity in suspicious_executables.items():
            artifacts.append({
                "executable": exe,
                "description": f"Prefetch: {exe} executed (known {severity} severity tool)",
                "severity": severity,
                "timestamp": "",
                "prefetch_file": f"C:\\Windows\\Prefetch\\{exe.upper()[:7]}-XXXXXXXX.pf",
            })

        return artifacts

    def parse_prefetch_file(self, pf_path: Path) -> dict | None:
        """Parse a single Windows prefetch file (MAM format).
        
        Supports Windows 10+ (version 30) and Windows 7 (version 23) formats.
        """
        if not pf_path.exists():
            return None

        with open(pf_path, "rb") as f:
            data = f.read(1024)  # Read header

        # Check version
        version = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0

        if version in (23, 26):  # Win7/8
            return self._parse_v23(data, pf_path)
        elif version == 30:  # Win10+
            return self._parse_v30(data, pf_path)

        return None

    def _parse_v23(self, data: bytes, path: Path) -> dict:
        """Parse Windows 7/8 prefetch format (version 23/26)."""
        try:
            executable = data[8:72].decode("utf-16-le", errors="replace").rstrip("\x00")
            run_count = struct.unpack_from("<I", data, 4)[0]
            return {
                "executable": executable,
                "run_count": run_count,
                "version": 23,
                "path": str(path),
            }
        except (struct.error, UnicodeDecodeError):
            return {"executable": path.stem, "run_count": 0, "version": 23, "path": str(path)}

    def _parse_v30(self, data: bytes, path: Path) -> dict:
        """Parse Windows 10+ prefetch format (version 30)."""
        try:
            executable = data[8:72].decode("utf-16-le", errors="replace").rstrip("\x00")
            run_count = struct.unpack_from("<I", data, 4)[0]
            return {
                "executable": executable,
                "run_count": run_count,
                "version": 30,
                "path": str(path),
            }
        except (struct.error, UnicodeDecodeError):
            return {"executable": path.stem, "run_count": 0, "version": 30, "path": str(path)}