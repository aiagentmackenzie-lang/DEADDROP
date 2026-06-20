"""Prefetch analyzer — parse Windows prefetch files for execution evidence."""

import struct
import uuid
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
                    artifact_id=str(uuid.uuid4())[:12],
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

        Known limitation: analyze() currently returns no artifacts because
        it needs filesystem-level access to prefetch .pf files within disk
        images. Use parse_prefetch_file() directly for extracted .pf files.
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

        Layout (v30 header):
        - Offset 0: Version (4 bytes)
        - Offset 4: Signature 'SCCA' (4 bytes)
        - Offset 8: Header size (4 bytes)
        - Offset 68: Run count (4 bytes) — after filename section in header
        - Offset 68+ varies by build; run_count commonly at offset 68 or 140

        Note: v30 prefetch format has a variable header layout. The run_count
        position varies by Windows build. We read from offset 68 as a common
        location and fall back to the filename from the path stem.
        """
        try:
            # Verify SCCA signature at offset 4
            sig = data[4:8]
            if sig != b"SCCA":
                # Not a valid v30 prefetch — fallback
                return {"executable": path.stem, "run_count": 0, "version": 30, "path": str(path)}

            # Run count — commonly at offset 68 in v30 format
            run_count = struct.unpack_from("<I", data, 68)[0] if len(data) >= 72 else 0
            # Executable name is typically at offset 112 as UTF-16-LE in v30
            executable = path.stem  # Default to filename stem
            if len(data) >= 240:  # Enough data for the name section
                try:
                    name_offset = 112  # Common v30 executable name offset
                    name_end = min(name_offset + 128, len(data))
                    raw_name = data[name_offset:name_end]
                    decoded = raw_name.decode("utf-16-le", errors="replace").rstrip("\x00")
                    if decoded and decoded.isprintable():
                        executable = decoded
                except (UnicodeDecodeError, struct.error):
                    pass
            return {
                "executable": executable,
                "run_count": run_count,
                "version": 30,
                "path": str(path),
            }
        except (struct.error, UnicodeDecodeError):
            return {"executable": path.stem, "run_count": 0, "version": 30, "path": str(path)}
