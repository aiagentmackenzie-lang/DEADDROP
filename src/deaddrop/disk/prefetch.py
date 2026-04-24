"""Prefetch analyzer — parse Windows prefetch files for execution evidence."""

import uuid
import struct
from pathlib import Path

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
        """Extract prefetch execution records.

        Returns empty list by default — actual prefetch file parsing
        via parse_prefetch_file() is needed to produce artifacts.
        Known suspicious executables are checked only against
        genuinely parsed prefetch entries.
        """
        # No fake artifacts — must parse actual .pf files
        return []

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
        """Parse Windows 7/8 prefetch format (version 23/26).

        Layout (simplified):
        - Offset 0: Version (4 bytes)
        - Offset 4: Run count (4 bytes)
        - Offset 8: Executable name (64 bytes, UTF-16-LE)
        """
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
        """Parse Windows 10+ prefetch format (version 30).

        Layout (simplified — v30 has a different header structure):
        - Offset 0: Version (4 bytes)
        - Offset 4: Signature (4 bytes, 'SCCA' = 0x41434353)
        - Offset 8: Run count (4 bytes)
        - Offset 12: Executable name offset (4 bytes)
        - The executable name is stored at a dynamic offset
          pointed to by offset 12, as UTF-16-LE null-terminated.
        """
        try:
            run_count = struct.unpack_from("<I", data, 8)[0]
            # Read executable name from dynamic offset
            name_offset = struct.unpack_from("<I", data, 12)[0]
            if name_offset < len(data) - 2:
                # Read up to 64 bytes of UTF-16-LE from the name offset
                name_end = min(name_offset + 128, len(data))
                raw_name = data[name_offset:name_end]
                executable = raw_name.decode("utf-16-le", errors="replace").rstrip("\x00")
            else:
                executable = path.stem
            return {
                "executable": executable,
                "run_count": run_count,
                "version": 30,
                "path": str(path),
            }
        except (struct.error, UnicodeDecodeError):
            return {"executable": path.stem, "run_count": 0, "version": 30, "path": str(path)}