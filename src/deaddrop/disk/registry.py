r"""Windows registry analyzer — parse registry hives for forensic artifacts.

Integrates python-registry (Registry.Registry) to actually walk hives and read
known forensic keys. The prior implementation only checked the \`regf\` magic
and returned one metadata row, so \`deaddrop analyze registry\` produced zero
artifacts on any real hive (SB-6). This parser opens each hive, walks the
FORENSIC_KEYS paths, and emits artifacts for the values it finds.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from deaddrop.core.case import CaseManager

log = logging.getLogger(__name__)

# Known forensic registry keys (paths are relative to the hive root; case-insensitive)
FORENSIC_KEYS: dict[str, list[str]] = {
    "run_keys": [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ],
    "services": [
        r"SYSTEM\CurrentControlSet\Services",
        r"SYSTEM\ControlSet001\Services",
    ],
    "usb_artifacts": [
        r"SYSTEM\CurrentControlSet\Enum\USBSTOR",
        r"SYSTEM\CurrentControlSet\Enum\USB",
    ],
    "browser": [
        r"SOFTWARE\Microsoft\Internet Explorer\Main",
        r"SOFTWARE\Microsoft\Edge\Main",
    ],
    "persistence": [
        r"Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
        r"Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad",
        r"Microsoft\Windows\CurrentVersion\Shell Extensions\Cached",
    ],
    "user_activity": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    ],
}

# Auto-start / persistence categories are high-severity by definition
_HIGH_SEVERITY_CATEGORIES = {"run_keys", "persistence", "services"}


class RegistryAnalyzer:
    """Analyze Windows registry hives for forensic artifacts."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def analyze(self, case_id: str, evidence_id: str | None = None) -> dict:
        """Analyze registry hives referenced by a case's disk evidence."""
        evidence_list = self.mgr.list_evidence(case_id)
        disk_evidence = [e for e in evidence_list if e["type"] == "disk"]
        if evidence_id:
            disk_evidence = [e for e in disk_evidence if e["id"] == evidence_id]

        total_keys = 0
        total_artifacts = 0

        for ev in disk_evidence:
            for artifact in self._extract_registry_artifacts(ev):
                self.mgr.add_artifact(
                    case_id=case_id,
                    evidence_id=ev["id"],
                    source="registry",
                    category=artifact["category"],
                    timestamp=artifact.get("timestamp", ""),
                    description=artifact["description"],
                    severity=artifact.get("severity", "info"),
                    data=str(artifact),
                    artifact_id=str(uuid.uuid4())[:12],
                )
                if artifact.get("timestamp"):
                    self.mgr.add_timeline_entry(
                        case_id=case_id,
                        source="registry",
                        timestamp=artifact["timestamp"],
                        description=artifact["description"],
                        severity=artifact.get("severity", "info"),
                        evidence_id=ev["id"],
                    )
                total_artifacts += 1
                total_keys += 1

        return {
            "keys_parsed": total_keys,
            "artifacts": total_artifacts,
        }

    def _extract_registry_artifacts(self, evidence: dict) -> list[dict]:
        r"""Parse every registry hive found next to the evidence path.

        If the evidence path is a directory, scan for hive files (SYSTEM,
        SOFTWARE, SAM, SECURITY, NTUSER.DAT, usrclass.dat). If it's a file with
        the \`regf\` magic, parse it directly. Returns [] when python-registry
        is unavailable or no hive parses.
        """
        try:
            from Registry import Registry
        except ImportError:
            log.warning("python-registry not installed; hive parsing unavailable. "
                        "Install with: pip install python-registry")
            return []

        path = Path(evidence["path"])
        hive_files: list[Path] = []
        if path.is_dir():
            for name in ("SYSTEM", "SOFTWARE", "SAM", "SECURITY",
                         "NTUSER.DAT", "ntuser.dat", "UsrClass.dat", "usrclass.dat"):
                p = path / name
                if p.exists():
                    hive_files.append(p)
        elif path.is_file() and self._looks_like_hive(path):
            hive_files = [path]

        artifacts: list[dict] = []
        for hive in hive_files:
            try:
                artifacts.extend(self._parse_hive(hive, Registry))
            except Exception as e:
                log.warning("Failed to parse hive %s: %s", hive, e)
        return artifacts

    @staticmethod
    def _looks_like_hive(path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) == b"regf"
        except OSError:
            return False

    def _parse_hive(self, hive_path: Path, Registry) -> list[dict]:
        """Open a hive and walk the FORENSIC_KEYS, emitting an artifact per value."""
        hive = Registry.Registry(str(hive_path))
        root = hive.root()
        artifacts: list[dict] = []
        hive_ts = root.timestamp().isoformat() if hasattr(root, "timestamp") else ""

        for category, key_paths in FORENSIC_KEYS.items():
            severity = "high" if category in _HIGH_SEVERITY_CATEGORIES else "info"
            for kp in key_paths:
                try:
                    key = root.find_key(kp)
                except Exception:
                    continue
                if not key:
                    continue
                # Emit one artifact per value in the key
                for val in key.values():
                    try:
                        val_str = str(val.value())
                    except Exception:
                        val_str = "<binary>"
                    name = val.name()
                    artifacts.append({
                        "category": category,
                        "key_path": kp,
                        "value_name": name,
                        "value": val_str[:500],
                        "description": f"[{category}] {kp}\\{name} = {val_str[:200]}",
                        "severity": severity,
                        "timestamp": key.timestamp().isoformat() if hasattr(key, "timestamp") else hive_ts,
                        "hive": hive_path.name,
                    })
                # Also emit one artifact per immediate subkey (e.g. per service,
                # per USB device) so the analyst sees the entries by name.
                for sub in key.subkeys():
                    artifacts.append({
                        "category": category,
                        "key_path": f"{kp}\\{sub.name()}",
                        "value_name": "",
                        "value": "",
                        "description": f"[{category}] {kp}\\{sub.name()}",
                        "severity": severity,
                        "timestamp": sub.timestamp().isoformat() if hasattr(sub, "timestamp") else hive_ts,
                        "hive": hive_path.name,
                    })
        return artifacts

    def parse_hive(self, hive_path: Path) -> list[dict]:
        """Parse a single hive file (legacy API used by tests)."""
        try:
            from Registry import Registry
        except ImportError:
            return []
        if not hive_path.exists() or not self._looks_like_hive(hive_path):
            return []
        return self._parse_hive(hive_path, Registry)
