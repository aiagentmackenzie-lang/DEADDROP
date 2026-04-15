"""Timeline export — CSV, JSON, and body file export."""

import csv
import json
from pathlib import Path
from datetime import datetime, timezone

from deaddrop.core.case import CaseManager


class TimelineExporter:
    """Export timelines in multiple formats."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def export(self, case_id: str, fmt: str, output_path: str | None = None) -> str:
        """Export timeline in specified format."""
        entries = self.mgr.get_timeline(case_id)

        if not output_path:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_dir = Path(f"deaddrop_exports/case_{case_id}")
            output_dir.mkdir(parents=True, exist_ok=True)
            ext = {"csv": ".csv", "json": ".json", "body": ".body"}
            output_path = str(output_dir / f"timeline_{ts}{ext.get(fmt, '.csv')}")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "csv":
            self._export_csv(entries, path)
        elif fmt == "json":
            self._export_json(entries, path)
        elif fmt == "body":
            self._export_body(entries, path)

        return str(path)

    def _export_csv(self, entries: list[dict], path: Path) -> None:
        """Export timeline as CSV."""
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "source", "severity", "description", "evidence_id", "artifact_id"])
            for entry in entries:
                writer.writerow([
                    entry.get("timestamp", ""),
                    entry.get("source", ""),
                    entry.get("severity", ""),
                    entry.get("description", ""),
                    entry.get("evidence_id", ""),
                    entry.get("artifact_id", ""),
                ])

    def _export_json(self, entries: list[dict], path: Path) -> None:
        """Export timeline as JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, default=str)

    def _export_body(self, entries: list[dict], path: Path) -> None:
        """Export in TSK body file format (mactime compatible).
        
        Body file format:
        MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
        """
        with open(path, "w", encoding="utf-8") as f:
            for entry in entries:
                # Convert ISO timestamp to Unix epoch
                ts = self._iso_to_epoch(entry.get("timestamp", ""))
                md5 = "0"  # Not available for timeline entries
                name = entry.get("description", "").replace("|", "_")[:255]
                inode = entry.get("artifact_id", "0")
                mode = "r/rrr"
                uid = "0"
                gid = "0"
                size = "0"
                atime = "0"
                mtime = str(ts) if ts else "0"
                ctime = str(ts) if ts else "0"
                crtime = "0"

                f.write(f"{md5}|{name}|{inode}|{mode}|{uid}|{gid}|{size}|{atime}|{mtime}|{ctime}|{crtime}\n")

    @staticmethod
    def _iso_to_epoch(iso_ts: str) -> int | None:
        """Convert ISO 8601 timestamp to Unix epoch."""
        if not iso_ts:
            return None
        try:
            dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
            return int(dt.timestamp())
        except (ValueError, TypeError):
            return None