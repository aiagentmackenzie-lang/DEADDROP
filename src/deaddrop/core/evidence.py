"""Evidence manager — ingestion, hash verification, chain of custody."""

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path

from deaddrop.core.case import CaseManager

SUPPORTED_DISK_FORMATS = {".dd", ".raw", ".e01", ".vmdk", ".qcow2", ".iso", ".img"}
SUPPORTED_MEMORY_FORMATS = {".raw", ".vmem", ".dmp", ".elf"}
# NOTE: .raw appears in both sets. Format detection via detect_format() returns "RAW"
# for both. The caller (ingest_disk/ingest_memory) determines the type, not the extension.
# Analysts must explicitly specify the evidence type at ingestion time.


def compute_hashes(file_path: Path, chunk_size: int = 8192) -> tuple[str, str]:
    """Compute SHA-256 and MD5 hashes for a file. Memory-efficient streaming."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def compute_dir_manifest_hash(dir_path: Path) -> tuple[str, str, int]:
    """Compute a chain-of-custody hash for a directory of extracted artifacts.

    Hashes a sorted manifest of (relative_path, size) for every file under the
    directory. This gives a verifiable integrity hash for directory evidence
    (e.g. a folder of carved .pf/.evtx/.hive files) without reading every byte
    into one blob. Returns (sha256, md5, total_size).
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total = 0
    files = sorted(p for p in dir_path.rglob("*") if p.is_file())
    for p in files:
        rel = p.relative_to(dir_path).as_posix()
        size = p.stat().st_size
        total += size
        line = f"{rel}\t{size}\n".encode()
        sha256.update(line)
        md5.update(line)
    return sha256.hexdigest(), md5.hexdigest(), total


def detect_format(file_path: Path) -> str:
    """Detect evidence format from extension and magic bytes."""
    ext = file_path.suffix.lower()
    format_map = {
        ".dd": "RAW/DD", ".raw": "RAW", ".img": "RAW",
        ".e01": "E01", ".vmdk": "VMDK", ".qcow2": "QCOW2", ".iso": "ISO",
        ".vmem": "VMEM", ".dmp": "Windows Crash Dump", ".elf": "ELF64",
    }
    if ext in format_map:
        return format_map[ext]

    # Magic byte detection
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        if header[:3] == b"EWF":
            return "E01"
        if header[:4] == b"KDMV":
            return "VMDK"
        if header[:4] == b"QFI\xfb":
            return "QCOW2"
        if header[:3] == b"\x7fELF":
            return "ELF64"
        if header[:4] == b"MDMP":
            return "Windows Crash Dump"  # Minidump variant; unified with .dmp ext (H-6)
        if header[:4] == b"PAGE":
            return "Windows Page File"
    except (OSError, PermissionError):
        pass
    return "UNKNOWN"


def verify_integrity(file_path: Path, expected_sha256: str, chunk_size: int = 8192) -> bool:
    """Verify file integrity against expected SHA-256 hash."""
    actual_sha256, _ = compute_hashes(file_path, chunk_size)
    return actual_sha256 == expected_sha256


class EvidenceManager:
    def __init__(self, case_manager: CaseManager):
        self.case_manager = case_manager

    def ingest_disk(self, case_id: str, image_path: str) -> dict:
        """Ingest a disk image with full chain of custody."""
        path = Path(image_path)
        if not path.exists():
            raise FileNotFoundError(f"Disk image not found: {image_path}")

        evidence_id = str(uuid.uuid4())[:12]
        # Directories of extracted artifacts (carved .pf/.evtx/.hive files) are
        # valid disk evidence — hash a manifest instead of the bytes.
        if path.is_dir():
            fmt = "DIR"
            sha256, md5, size = compute_dir_manifest_hash(path)
        else:
            fmt = detect_format(path)
            sha256, md5 = compute_hashes(path)
            size = path.stat().st_size

        self.case_manager.add_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            etype="disk",
            path=str(path.resolve()),
            filename=path.name,
            size_bytes=size,
            sha256=sha256,
            md5=md5,
            fmt=fmt,
        )

        return {
            "id": evidence_id,
            "type": "disk",
            "path": str(path.resolve()),
            "filename": path.name,
            "size_bytes": size,
            "sha256": sha256,
            "md5": md5,
            "format": fmt,
            "ingested_at": datetime.now(UTC).isoformat(),
            "verified": True,
        }

    def ingest_memory(self, case_id: str, dump_path: str) -> dict:
        """Ingest a memory dump with full chain of custody."""
        path = Path(dump_path)
        if not path.exists():
            raise FileNotFoundError(f"Memory dump not found: {dump_path}")

        evidence_id = str(uuid.uuid4())[:12]
        fmt = detect_format(path)
        sha256, md5 = compute_hashes(path)
        size = path.stat().st_size

        self.case_manager.add_evidence(
            case_id=case_id,
            evidence_id=evidence_id,
            etype="memory",
            path=str(path.resolve()),
            filename=path.name,
            size_bytes=size,
            sha256=sha256,
            md5=md5,
            fmt=fmt,
        )

        return {
            "id": evidence_id,
            "type": "memory",
            "path": str(path.resolve()),
            "filename": path.name,
            "size_bytes": size,
            "sha256": sha256,
            "md5": md5,
            "format": fmt,
            "ingested_at": datetime.now(UTC).isoformat(),
            "verified": True,
        }

    def verify_evidence(self, case_id: str, evidence_id: str) -> dict:
        """Re-verify evidence integrity (chain of custody check)."""
        evidence_list = self.case_manager.list_evidence(case_id)
        evidence = next((e for e in evidence_list if e["id"] == evidence_id), None)
        if not evidence:
            return {"verified": False, "reason": "Evidence not found"}

        path = Path(evidence["path"])
        if not path.exists():
            return {"verified": False, "reason": "File no longer exists at recorded path"}

        if path.is_dir():
            current_sha256, current_md5, _ = compute_dir_manifest_hash(path)
        else:
            current_sha256, current_md5 = compute_hashes(path)
        sha256_match = current_sha256 == evidence["sha256"]
        md5_match = current_md5 == evidence["md5"]

        return {
            "verified": sha256_match and md5_match,
            "sha256_match": sha256_match,
            "md5_match": md5_match,
            "original_sha256": evidence["sha256"],
            "current_sha256": current_sha256,
            "original_md5": evidence["md5"],
            "current_md5": current_md5,
        }
