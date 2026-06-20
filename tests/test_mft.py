"""Tests for MFT Parser — NTFS Master File Table parsing."""

import struct

import pytest

from deaddrop.core.case import CaseManager
from deaddrop.disk.mft import MFTParser


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


def make_mft_entry(sequence=1, flags=0x01, filename="", offset=0):
    """Craft a minimal valid MFT entry (1024 bytes)."""
    data = bytearray(1024)

    # FILE signature
    data[0:4] = b"FILE"

    # Fixup offset and count
    struct.pack_into("<H", data, 4, 48)  # fixup_offset
    struct.pack_into("<H", data, 6, 3)   # fixup_count

    # Sequence number
    struct.pack_into("<H", data, 16, sequence)

    # Used size
    struct.pack_into("<I", data, 24, 256)

    # Flags
    struct.pack_into("<H", data, 22, flags)

    # First attribute offset
    attr_offset = 56
    struct.pack_into("<H", data, 20, attr_offset)

    # Write a $FILE_NAME attribute if filename provided
    if filename:
        fn_data = filename.encode("utf-16-le")
        name_len = len(filename)
        # $FILE_NAME attribute header
        struct.pack_into("<I", data, attr_offset, 0x30)  # type
        struct.pack_into("<H", data, attr_offset + 4, 66 + name_len * 2)  # length
        struct.pack_into("<H", data, attr_offset + 6, 24)  # content offset

        # Name length and name
        data[attr_offset + 64] = name_len
        fn_start = attr_offset + 66
        data[fn_start:fn_start + len(fn_data)] = fn_data

    return bytes(data)


class TestMFTParser:
    def test_parse_valid_entry(self, case_mgr, tmp_path):
        """Parse a valid MFT entry with FILE signature."""
        mft_file = tmp_path / "test.mft"
        entry = make_mft_entry(sequence=5, flags=0x03, filename="test.txt")
        mft_file.write_bytes(entry)

        parser = MFTParser(case_mgr)
        results = parser.parse_mft(mft_file)
        assert len(results) == 1
        assert results[0]["is_directory"] is True  # flags 0x03 includes directory flag
        assert results[0]["sequence"] == 5

    def test_reject_invalid_entry(self, case_mgr, tmp_path):
        """Entries without FILE signature are skipped."""
        mft_file = tmp_path / "bad.mft"
        data = b"\x00" * 1024  # No FILE signature
        mft_file.write_bytes(data)

        parser = MFTParser(case_mgr)
        results = parser.parse_mft(mft_file)
        assert results == []

    def test_deleted_entry(self, case_mgr, tmp_path):
        """Entries with flags=0x02 (directory, not in use) are marked deleted."""
        mft_file = tmp_path / "deleted.mft"
        entry = make_mft_entry(flags=0x02)  # directory but not in use
        mft_file.write_bytes(entry)

        parser = MFTParser(case_mgr)
        results = parser.parse_mft(mft_file)
        assert len(results) == 1
        assert results[0]["is_deleted"] is True

    def test_multiple_entries(self, case_mgr, tmp_path):
        """Parse multiple MFT entries from one file."""
        mft_file = tmp_path / "multi.mft"
        entry1 = make_mft_entry(sequence=1, flags=0x01, filename="file1.txt")
        entry2 = make_mft_entry(sequence=2, flags=0x03, filename="dir1")
        mft_file.write_bytes(entry1 + entry2)

        parser = MFTParser(case_mgr)
        results = parser.parse_mft(mft_file)
        assert len(results) == 2

    def test_empty_file(self, case_mgr, tmp_path):
        """Empty MFT file returns empty results."""
        mft_file = tmp_path / "empty.mft"
        mft_file.write_bytes(b"")

        parser = MFTParser(case_mgr)
        results = parser.parse_mft(mft_file)
        assert results == []

    def test_nonexistent_file(self, case_mgr, tmp_path):
        """Nonexistent file returns empty results."""
        parser = MFTParser(case_mgr)
        results = parser.parse_mft(tmp_path / "nonexistent.mft")
        assert results == []


class TestFiletimeConversion:
    def test_zero_filetime(self):
        """Zero filetime returns empty string."""
        result = MFTParser._filetime_to_iso(0)
        assert result == ""

    def test_valid_filetime(self):
        """Valid Windows FILETIME converts to ISO 8601."""
        # 2024-01-15 12:00:00 UTC ≈ 133586064000000000 (100ns intervals)
        # Let's test with a known value
        result = MFTParser._filetime_to_iso(133586064000000000)
        assert result  # Not empty
        assert "2024" in result

    def test_negative_filetime(self):
        """Negative filetime (before epoch) returns empty string."""
        result = MFTParser._filetime_to_iso(1)
        # 1 * 100ns from 1601 is still way before 1970
        assert result == ""
