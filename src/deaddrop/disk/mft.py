"""MFT parser — parse Windows Master File Table entries."""

import uuid
import struct
from pathlib import Path
from datetime import datetime, timezone

from deaddrop.core.case import CaseManager


# MFT entry attributes
ATTRIBUTE_TYPES = {
    0x10: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    0x80: "$DATA",
    0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP",
    0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION",
    0xE0: "$EA",
    0xF0: "$PROPERTY_SET",
    0x100: "$LOGGED_UTILITY_STREAM",
}

# MFT entry flags
ENTRY_FLAGS = {
    0x01: "In Use",
    0x02: "Is Directory",
    0x04: "Is Extended",
    0x08: "Is View Index",
}


class MFTParser:
    """Parse Windows NTFS Master File Table for forensic evidence."""

    def __init__(self, case_manager: CaseManager):
        self.mgr = case_manager

    def parse_mft(self, mft_path: Path) -> list[dict]:
        """Parse an MFT file and extract entry metadata."""
        entries = []
        if not mft_path.exists():
            return entries

        # Standard MFT entry size is 1024 bytes
        entry_size = 1024

        with open(mft_path, "rb") as f:
            offset = 0
            while True:
                data = f.read(entry_size)
                if len(data) < entry_size:
                    break

                # Check for FILE signature
                if data[:4] != b"FILE":
                    offset += entry_size
                    continue

                entry = self._parse_entry(data, offset)
                if entry:
                    entries.append(entry)

                offset += entry_size

                # Safety cap
                if len(entries) >= 100000:
                    break

        return entries

    def _parse_entry(self, data: bytes, offset: int) -> dict | None:
        """Parse a single MFT entry."""
        try:
            # Entry header
            signature = data[:4]
            fixup_offset = struct.unpack_from("<H", data, 4)[0]
            fixup_count = struct.unpack_from("<H", data, 6)[0]
            sequence_number = struct.unpack_from("<H", data, 16)[0]
            flags = struct.unpack_from("<H", data, 22)[0]
            used_size = struct.unpack_from("<I", data, 24)[0]

            # Decode flags
            flag_names = [name for mask, name in ENTRY_FLAGS.items() if flags & mask]
            is_deleted = not (flags & 0x01)
            is_directory = bool(flags & 0x02)

            # Parse attributes to find $FILE_NAME
            filename = ""
            timestamps = {}
            attr_offset = struct.unpack_from("<H", data, 20)[0]

            pos = attr_offset
            while pos < used_size - 4:
                attr_type = struct.unpack_from("<I", data, pos)[0]
                if attr_type == 0xFFFFFFFF:  # End of attributes
                    break
                attr_len = struct.unpack_from("<H", data, pos + 4)[0]
                if attr_len == 0:
                    break

                if attr_type == 0x30 and attr_len > 66:  # $FILE_NAME
                    # Extract filename from $FILE_NAME attribute
                    name_offset = struct.unpack_from("<H", data, pos + 6)[0]
                    name_pos = pos + name_offset
                    # Skip the $FILE_NAME header (66 bytes from attr start)
                    fn_header_size = 66
                    if pos + fn_header_size + 2 < len(data):
                        name_len = data[pos + fn_header_size]
                        name_pos = pos + fn_header_size + 2
                        if name_pos + name_len * 2 <= len(data):
                            filename = data[name_pos:name_pos + name_len * 2].decode("utf-16-le", errors="replace")

                elif attr_type == 0x10 and attr_len > 72:  # $STANDARD_INFORMATION
                    si_offset = struct.unpack_from("<H", data, pos + 6)[0]
                    si_pos = pos + si_offset
                    if si_pos + 72 <= len(data):
                        # Windows FILETIME timestamps (100ns intervals since 1601-01-01)
                        crtime = struct.unpack_from("<Q", data, si_pos)[0]
                        mtime = struct.unpack_from("<Q", data, si_pos + 8)[0]
                        atime = struct.unpack_from("<Q", data, si_pos + 16)[0]
                        rtime = struct.unpack_from("<Q", data, si_pos + 24)[0]

                        timestamps = {
                            "created": self._filetime_to_iso(crtime),
                            "modified": self._filetime_to_iso(mtime),
                            "accessed": self._filetime_to_iso(atime),
                            "record_modified": self._filetime_to_iso(rtime),
                        }

                pos += attr_len

            return {
                "offset": offset,
                "entry_number": offset // 1024,
                "sequence": sequence_number,
                "flags": flag_names,
                "is_deleted": is_deleted,
                "is_directory": is_directory,
                "filename": filename,
                "timestamps": timestamps,
                "severity": "medium" if is_deleted else "info",
            }

        except (struct.error, IndexError):
            return None

    @staticmethod
    def _filetime_to_iso(filetime: int) -> str:
        """Convert Windows FILETIME (100ns since 1601-01-01) to ISO 8601."""
        if filetime == 0:
            return ""
        try:
            # FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
            # Difference: 11644473600 seconds
            unix_ts = (filetime / 10_000_000) - 11644473600
            if unix_ts < 0:
                return ""
            return datetime.fromtimestamp(unix_ts, tz=timezone.utc).isoformat()
        except (OSError, ValueError, OverflowError):
            return ""