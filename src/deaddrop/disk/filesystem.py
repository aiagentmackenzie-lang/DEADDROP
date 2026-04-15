"""Filesystem analyzer — parse filesystem structures from disk images."""

import uuid
from pathlib import Path
from datetime import datetime, timezone

from deaddrop.core.case import CaseManager


class FilesystemAnalyzer:
    """Analyze filesystem structures from disk images.
    
    Uses pytsk3 when available, falls back to raw binary parsing.
    """

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def analyze(self, case_id: str, evidence_id: str | None = None) -> dict:
        """Run filesystem analysis on all disk evidence in a case."""
        evidence_list = self.mgr.list_evidence(case_id)
        disk_evidence = [e for e in evidence_list if e["type"] == "disk"]
        if evidence_id:
            disk_evidence = [e for e in disk_evidence if e["id"] == evidence_id]

        total_files = 0
        deleted_files = 0
        carved_files = 0
        sources = []

        for ev in disk_evidence:
            image_path = Path(ev["path"])
            if not image_path.exists():
                continue

            # Try pytsk3 first
            try:
                results = self._analyze_with_tsk(image_path)
            except ImportError:
                results = self._analyze_raw(image_path)

            # Store artifacts
            for entry in results.get("entries", []):
                self.mgr.add_artifact(
                    case_id=case_id,
                    evidence_id=ev["id"],
                    source="filesystem",
                    category=entry.get("category", "file"),
                    timestamp=entry.get("timestamp", ""),
                    description=entry.get("description", ""),
                    severity=entry.get("severity", "info"),
                    data=str(entry),
                    artifact_id=str(uuid.uuid4())[:8],
                )
                # Add to timeline
                if entry.get("timestamp"):
                    self.mgr.add_timeline_entry(
                        case_id=case_id,
                        source="filesystem",
                        timestamp=entry["timestamp"],
                        description=entry.get("description", ""),
                        severity=entry.get("severity", "info"),
                        evidence_id=ev["id"],
                    )

            total_files += results.get("total_files", 0)
            deleted_files += results.get("deleted_files", 0)
            carved_files += results.get("carved_files", 0)
            sources.append(ev["id"])

        return {
            "total_files": total_files,
            "deleted_files": deleted_files,
            "carved_files": carved_files,
            "sources": sources,
        }

    def _analyze_with_tsk(self, image_path: Path) -> dict:
        """Analyze using The Sleuth Kit Python bindings (pytsk3)."""
        import pytsk3

        entries = []
        total = 0
        deleted = 0

        try:
            img_info = pytsk3.Img_Info(str(image_path))
            fs_info = pytsk3.FS_Info(img_info)
            root = fs_info.open_dir(path="/")

            def walk_dir(directory, path="/"):
                nonlocal total, deleted
                for entry in directory:
                    name = entry.info.name.name
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    if name in (".", ".."):
                        continue

                    full_path = path + name
                    meta = entry.info.meta
                    is_deleted = False
                    timestamp = ""

                    if meta:
                        is_deleted = meta.flags & 0x02 != 0  # TSK_FS_NAME_FLAG_UNALLOC
                        try:
                            ts = meta.crtime
                            if ts and ts > 0:
                                timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                        except (OSError, ValueError):
                            pass

                    total += 1
                    if is_deleted:
                        deleted += 1

                    entries.append({
                        "path": full_path,
                        "category": "deleted_file" if is_deleted else "file",
                        "timestamp": timestamp,
                        "description": f"{'[DELETED] ' if is_deleted else ''}{full_path}",
                        "severity": "medium" if is_deleted else "info",
                        "size": meta.size if meta and hasattr(meta, "size") else 0,
                    })

                    # Recurse into directories
                    if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        try:
                            subdir = fs_info.open_dir(inode=meta.addr)
                            walk_dir(subdir, full_path + "/")
                        except Exception:
                            pass

            walk_dir(root)
        except Exception as e:
            # Fallback to raw analysis
            return self._analyze_raw(image_path)

        return {
            "total_files": total,
            "deleted_files": deleted,
            "carved_files": 0,
            "entries": entries[:5000],  # Cap to prevent memory issues
        }

    def _analyze_raw(self, image_path: Path) -> dict:
        """Basic raw analysis when pytsk3 is unavailable."""
        # Minimal: report file metadata
        entries = []
        size = image_path.stat().st_size
        entries.append({
            "path": str(image_path),
            "category": "disk_image",
            "timestamp": datetime.fromtimestamp(image_path.stat().st_mtime, tz=timezone.utc).isoformat(),
            "description": f"Disk image: {image_path.name} ({size:,} bytes)",
            "severity": "info",
            "size": size,
        })
        return {
            "total_files": 1,
            "deleted_files": 0,
            "carved_files": 0,
            "entries": entries,
        }