"""Volatility3 wrapper — run memory forensics plugins through DEADDROP."""

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import ClassVar

from deaddrop.core.case import CaseManager

# Common Volatility3 plugins for forensic analysis
DEFAULT_PLUGINS = {
    "windows.pslist": "List processes",
    "windows.pstree": "Process tree",
    "windows.psscan": "Scan for processes (including hidden)",
    "windows.cmdscan": "Command history",
    "windows.consoles": "Console history",
    "windows.dlllist": "List DLLs per process",
    "windows.handles": "List handles per process",
    "windows.malfind": "Find injected code/malware",
    "windows.netscan": "Network connections (Win7+)",
    "windows.netstat": "Network connections",
    "windows.registry.hivelist": "List registry hives",
    "windows.registry.printkey": "Print registry key values",
    "windows.filescan": "Scan for file objects",
    "windows.mutantscan": "Scan for mutexes",
    "windows.ssdt": "System Service Dispatch Table",
    "windows.callbacks": "Kernel callbacks",
    "windows.devicetree": "Device tree",
    "windows.envars": "Environment variables",
    "windows.info": "OS information",
    "windows.vadyarascan": "YARA scan process memory",
    "windows.virtmap": "Virtual memory map",
}


class VolatilityWrapper:
    """Wrapper around Volatility3 for memory forensics analysis."""

    def __init__(self, case_manager: CaseManager, volatility_path: str | None = None):
        self.mgr = case_manager
        self.volatility_path = volatility_path or self._find_volatility()

    def _find_volatility(self) -> str:
        """Find Volatility3 installation."""
        # Check if vol is in PATH
        vol = shutil.which("vol")
        if vol:
            return vol
        # Check common locations
        common_paths = [
            Path.home() / "volatility3" / "vol.py",
            Path("/usr/local/bin/vol"),
            Path("/opt/volatility3/vol.py"),
        ]
        for p in common_paths:
            if p.exists():
                return str(p)
        return "vol"

    # Allowed Volatility3 plugins — prevents command injection via plugin name
    ALLOWED_PLUGINS: ClassVar[set[str]] = set(DEFAULT_PLUGINS.keys())

    def run_plugin(self, case_id: str, evidence_id: str | None, plugin: str) -> dict:
        """Run a Volatility3 plugin against memory evidence in a case."""
        # Validate plugin name to prevent command injection
        if plugin not in self.ALLOWED_PLUGINS:
            return {"findings_count": 0, "error": f"Unknown plugin: {plugin}"}

        evidence_list = self.mgr.list_evidence(case_id)
        memory_evidence = [e for e in evidence_list if e["type"] == "memory"]
        if evidence_id:
            memory_evidence = [e for e in memory_evidence if e["id"] == evidence_id]

        if not memory_evidence:
            return {"findings_count": 0, "error": "No memory evidence found in case"}

        findings = []
        for ev in memory_evidence:
            result = self._execute_plugin(ev["path"], plugin)
            if result:
                # Store as artifacts
                for finding in result.get("findings", []):
                    self.mgr.add_artifact(
                        case_id=case_id,
                        evidence_id=ev["id"],
                        source="memory",
                        category="memory_forensics",
                        timestamp=finding.get("timestamp", ""),
                        description=finding.get("description", ""),
                        severity=finding.get("severity", "info"),
                        data=str(finding),
                        artifact_id=str(uuid.uuid4())[:12],
                    )
                    if finding.get("timestamp"):
                        self.mgr.add_timeline_entry(
                            case_id=case_id,
                            source="memory",
                            timestamp=finding["timestamp"],
                            description=finding["description"],
                            severity=finding.get("severity", "info"),
                            evidence_id=ev["id"],
                        )
                findings.extend(result.get("findings", []))

        return {"findings_count": len(findings), "plugin": plugin}

    def _execute_plugin(self, dump_path: str, plugin: str) -> dict | None:
        """Execute a Volatility3 plugin and parse output."""
        try:
            cmd = [
                self.volatility_path,
                "-f", dump_path,
                plugin,
                "--output-format", "json",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                return {"findings": [], "error": result.stderr[:500]}

            # Parse JSON output
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Fallback: parse tabular output
                return self._parse_tabular_output(result.stdout, plugin)

            findings = []
            if isinstance(data, list):
                for row in data[:1000]:
                    finding = self._row_to_finding(row, plugin)
                    if finding:
                        findings.append(finding)
            elif isinstance(data, dict) and "rows" in data:
                for row in data["rows"][:1000]:
                    finding = self._row_to_finding(row, plugin)
                    if finding:
                        findings.append(finding)

            return {"findings": findings}

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return {"findings": [], "error": str(e)}

    def _parse_tabular_output(self, output: str, plugin: str) -> dict:
        """Parse Volatility3 tabular text output into findings."""
        findings = []
        lines = output.strip().split("\n")
        # Skip header row (first non-separator line) and Volatility banner
        header_skipped = False
        for line in lines:
            if not line or line.startswith(("Volatility", "=")):
                continue
            # Skip the first data line as column header
            if not header_skipped:
                header_skipped = True
                continue
            findings.append({
                "description": f"[{plugin}] {line.strip()}",
                "severity": "info",
                "timestamp": "",
                "plugin": plugin,
                "raw": line.strip(),
            })
        return {"findings": findings[:1000]}

    def _row_to_finding(self, row: dict | list, plugin: str) -> dict | None:
        """Convert a Volatility3 output row to a DEADDROP finding."""
        if isinstance(row, dict):
            # Check for suspicious indicators
            severity = "info"
            desc_parts = []

            # Process name checks
            proc_name = row.get("Process", row.get("ImageFileName", ""))
            suspicious_procs = {"mimikatz", "procdump", "psexec", "cmd.exe", "powershell.exe"}
            if any(s in str(proc_name).lower() for s in suspicious_procs):
                severity = "high"

            # PID
            pid = row.get("PID", row.get("UniqueProcessId", ""))
            if pid:
                desc_parts.append(f"PID={pid}")

            # Build description
            for key in ["Process", "ImageFileName", "Offset", "Name"]:
                if row.get(key):
                    desc_parts.append(f"{key}={row[key]}")

            description = f"[{plugin}] " + " | ".join(desc_parts) if desc_parts else f"[{plugin}] {row}"

            return {
                "description": description,
                "severity": severity,
                "timestamp": row.get("CreateTime", row.get("Timestamp", "")),
                "plugin": plugin,
                "raw": str(row),
            }

        elif isinstance(row, (list, tuple)) and len(row) > 0:
            return {
                "description": f"[{plugin}] {' | '.join(str(v) for v in row[:5])}",
                "severity": "info",
                "timestamp": "",
                "plugin": plugin,
                "raw": str(row),
            }

        return None

    def list_plugins(self) -> dict[str, str]:
        """List available Volatility3 plugins."""
        return DEFAULT_PLUGINS.copy()
