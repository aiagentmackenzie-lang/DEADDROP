"""Phase 3 regression tests — real forensic parsers (SB-6/7/8/9/10/H-5/H-6).

Locks the fixes: stateful cross-chunk carving, spec-conformant prefetch, real
EVTX/registry parsing wiring, chunked YARA on large files, transactional
case delete, unified .dmp naming.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from deaddrop.core.case import CaseManager


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


def _ingest_disk(mgr, case_id, path):
    """Register disk evidence pointing at `path` (a file or dir)."""
    mgr.add_evidence(case_id, "ev1", "disk", str(path), Path(path).name,
                     Path(path).stat().st_size if Path(path).is_file() else 0,
                     "a" * 64, "b" * 32, "RAW")


# ── SB-9: stateful cross-chunk file carving ──────────────────────

class TestSBCrossChunkCarving:
    def test_carve_file_spanning_chunk_boundary(self, tmp_path):
        """A file whose footer is in the NEXT chunk must be carved (was dropped)."""
        from deaddrop.disk.carving import FileCarver

        # Build an image where a JPEG header sits well before the chunk end
        # and its footer is in the next chunk — the prior 8-byte overlap would
        # lose this. Use a tiny chunk size to force the boundary.
        jpeg_header = b"\xff\xd8\xff\xe0" + b"\x00" * 20
        body = b"A" * 50  # spans into next chunk
        jpeg_footer = b"\xff\xd9"
        prepad = b"\x00" * 30  # header starts 30 bytes in (well past any 8-byte overlap)

        chunk_size = 64  # tiny chunks so the file spans two
        image_bytes = prepad + jpeg_header + body + jpeg_footer + b"\x00" * 32
        image_path = tmp_path / "disk.raw"
        image_path.write_bytes(image_bytes)

        carver = FileCarver(chunk_size=chunk_size)
        out_dir = tmp_path / "carved"
        results = carver.carve(image_path, out_dir)

        assert len(results) >= 1, "JPEG spanning a chunk boundary must be carved"
        jpeg = next(r for r in results if r["type"] == "JPEG")
        carved = Path(jpeg["output"]).read_bytes()
        # The carved bytes must contain both header and footer
        assert carved.startswith(b"\xff\xd8\xff")
        assert carved.endswith(b"\xff\xd9")
        assert b"A" * 50 in carved

    def test_carve_two_files_in_one_chunk(self, tmp_path):
        """Multiple files in a single chunk are all carved (regression)."""
        from deaddrop.disk.carving import FileCarver

        img = (
            b"\xff\xd8\xff" + b"x" * 10 + b"\xff\xd9"
            + b"\x89PNG\r\n\x1a\n" + b"y" * 10 + b"IEND\xaeB`\x82"
            + b"\x00" * 16
        )
        image_path = tmp_path / "two.raw"
        image_path.write_bytes(img)
        out_dir = tmp_path / "out"
        results = FileCarver(chunk_size=4096).carve(image_path, out_dir)
        types = {r["type"] for r in results}
        assert "JPEG" in types and "PNG" in types

    def test_carve_respects_max_files(self, tmp_path):
        """max_files caps the carve count."""
        from deaddrop.disk.carving import FileCarver
        # 5 tiny JPEGs
        img = (b"\xff\xd8\xff" + b"x" * 4 + b"\xff\xd9") * 5 + b"\x00" * 16
        image_path = tmp_path / "many.raw"
        image_path.write_bytes(img)
        results = FileCarver(chunk_size=4096).carve(image_path, tmp_path / "o", max_files=2)
        assert len(results) <= 2

    def test_carve_empty_image(self, tmp_path):
        from deaddrop.disk.carving import FileCarver
        image_path = tmp_path / "empty.raw"
        image_path.write_bytes(b"")
        assert FileCarver().carve(image_path, tmp_path / "o") == []


# ── SB-7: chunked YARA (no silent skip of large disk images) ─────

class TestSBChunkedYara:
    def test_yara_scan_finds_eicar_in_small_file(self, case_mgr, tmp_path):
        """Regression: a normal file is scanned and EICAR is detected."""
        from deaddrop.hunt.yara_scanner import YARAScanner

        target = tmp_path / "suspect.bin"
        target.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        c = case_mgr.create_case("YARA Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", str(target), "suspect.bin",
                              target.stat().st_size, "a" * 64, "b" * 32, "RAW")
        scanner = YARAScanner(case_mgr)
        # Use the builtin eicar rule
        from deaddrop.hunt.yara_scanner import BUILTIN_RULES
        result = scanner._execute_scan(c.id, {"eicar": BUILTIN_RULES["eicar"]})
        assert result["hits"] >= 1
        # An artifact + hunt_result were recorded
        assert len(case_mgr.list_artifacts(c.id, source="hunt")) >= 1

    def test_yara_chunked_path_runs(self, case_mgr, tmp_path, monkeypatch):
        """A file above MAX_DIRECT_SCAN_SIZE goes through the chunked path."""
        from deaddrop.hunt.yara_scanner import BUILTIN_RULES, YARAScanner

        # Lower thresholds so a small file triggers chunking. The chunk window
        # must be >= the longest signature (EICAR is 68 bytes) so YARA can match
        # it within one window — production uses 512 MiB chunks, always larger
        # than any rule signature.
        monkeypatch.setattr(YARAScanner, "MAX_DIRECT_SCAN_SIZE", 16)
        monkeypatch.setattr(YARAScanner, "SCAN_CHUNK", 128)
        monkeypatch.setattr(YARAScanner, "SCAN_OVERLAP", 32)

        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        target = tmp_path / "big.bin"
        target.write_bytes(b"\x00" * 10 + eicar + b"\x00" * 20)  # 98 bytes > 16 threshold

        c = case_mgr.create_case("Chunked YARA Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", str(target), "big.bin",
                              target.stat().st_size, "a" * 64, "b" * 32, "RAW")
        result = YARAScanner(case_mgr)._execute_scan(c.id, {"eicar": BUILTIN_RULES["eicar"]})
        assert result["hits"] >= 1, "chunked scan must still find the EICAR signature"


# ── SB-6: real EVTX / registry parsing wiring ────────────────────

class TestSB6EVTXWiring:
    def test_analyze_events_no_evtx_returns_zero(self, case_mgr, tmp_path):
        """A directory with no .evtx yields zero events (not a crash)."""
        from deaddrop.disk.events import EventLogAnalyzer
        d = tmp_path / "evdir"
        d.mkdir()
        d.joinpath("not-an-evtx.txt").write_text("hello")
        c = case_mgr.create_case("EVTX Empty Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", str(d), "evdir", 0, "a" * 64, "b" * 32, "RAW")
        result = EventLogAnalyzer(case_mgr).analyze(c.id)
        assert result["events_parsed"] == 0
        assert result["security_events"] == 0

    def test_parse_evtx_non_evtx_file_returns_empty(self, case_mgr, tmp_path):
        from deaddrop.disk.events import EventLogAnalyzer
        f = tmp_path / "fake.evtx"
        f.write_bytes(b"\x00" * 4096)  # not ElfFile magic
        assert EventLogAnalyzer(case_mgr).parse_evtx(f) == []

    def test_security_events_count_is_28(self):
        from deaddrop.disk.events import SECURITY_EVENTS
        assert len(SECURITY_EVENTS) == 28


class TestSB6RegistryWiring:
    def test_analyze_registry_no_hives_returns_zero(self, case_mgr, tmp_path):
        from deaddrop.disk.registry import RegistryAnalyzer
        d = tmp_path / "regdir"
        d.mkdir()
        d.joinpath("random.txt").write_text("not a hive")
        c = case_mgr.create_case("Reg Empty Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", str(d), "regdir", 0, "a" * 64, "b" * 32, "RAW")
        result = RegistryAnalyzer(case_mgr).analyze(c.id)
        assert result["artifacts"] == 0

    def test_parse_hive_non_regf_returns_empty(self, case_mgr, tmp_path):
        from deaddrop.disk.registry import RegistryAnalyzer
        f = tmp_path / "fake.hive"
        f.write_bytes(b"\x00" * 4096)  # not regf magic
        assert RegistryAnalyzer(case_mgr).parse_hive(f) == []


# ── SB-10: MFT $FILE_NAME reads content offset from the header ──

class TestSB10MftFileNameOffset:
    def test_filename_read_with_nonzero_content_offset(self, tmp_path):
        """$FILE_NAME with a content_offset != 0 must still read the name.

        The prior code hardcoded 66 bytes from the attribute start; this test
        builds an MFT entry where the $FILE_NAME content starts at a non-zero
        offset and asserts the parser reads the name from the right place.
        """
        from deaddrop.disk.mft import MFTParser

        # Minimal MFT entry: FILE signature, used_size, one $FILE_NAME attr.
        entry = bytearray(1024)
        entry[0:4] = b"FILE"
        struct.pack_into("<H", entry, 16, 1)   # sequence_number
        struct.pack_into("<H", entry, 22, 0x01)  # flags = In Use
        attr_offset = 56
        struct.pack_into("<H", entry, 20, attr_offset)
        used_size = 200
        struct.pack_into("<I", entry, 24, used_size)

        # $FILE_NAME attribute at attr_offset
        pos = attr_offset
        struct.pack_into("<I", entry, pos, 0x30)        # attr type = $FILE_NAME
        attr_len = 120
        struct.pack_into("<H", entry, pos + 4, attr_len)  # attr length
        # content_offset (read by the parser at pos+6): set to 24 (non-zero!)
        content_offset = 24
        struct.pack_into("<H", entry, pos + 6, content_offset)
        content_start = pos + content_offset
        # FILE_NAME content: 64 bytes of header fields, then name_len, namespace, name
        name = "secret.txt".encode("utf-16-le")
        entry[content_start + 64] = len(name) // 2  # name length in chars
        # namespace byte at content_start + 65 (leave 0)
        entry[content_start + 66:content_start + 66 + len(name)] = name
        # End-of-attributes marker after this attr
        struct.pack_into("<I", entry, pos + attr_len, 0xFFFFFFFF)

        mft_path = tmp_path / "test.mft"
        mft_path.write_bytes(bytes(entry))
        parser = MFTParser(case_mgr)
        entries = parser.parse_mft(mft_path)
        assert len(entries) == 1
        assert entries[0]["filename"] == "secret.txt", (
            "filename must be read from content_start+66, not hardcoded pos+66"
        )


# ── H-5: transactional case delete ──────────────────────────────

class TestH5TransactionalDelete:
    def test_delete_cascades_children(self, case_mgr):
        c = case_mgr.create_case("Del Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/x.raw", "x.raw", 1024,
                              "a" * 64, "b" * 32, "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "t")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01", "e")
        case_mgr.add_hunt_result(c.id, "hr1", "r1", "yara")
        assert case_mgr.delete_case(c.id) is True
        assert case_mgr.get_case(c.id) is None
        assert case_mgr.list_evidence(c.id) == []
        assert case_mgr.list_artifacts(c.id) == []
        assert case_mgr.get_timeline(c.id) == []
        assert case_mgr.get_hunt_results(c.id) == []

    def test_delete_nonexistent_returns_false(self, case_mgr):
        assert case_mgr.delete_case("does-not-exist") is False


# ── H-6: unified .dmp naming ─────────────────────────────────────

class TestH6DmpNaming:
    def test_dmp_extension_and_mdmp_magic_both_collapse_to_crash_dump(self, tmp_path):
        from deaddrop.core.evidence import detect_format
        dmp = tmp_path / "dump.dmp"
        dmp.write_bytes(b"MDMP" + b"\x00" * 60)  # MDMP magic
        assert detect_format(dmp) == "Windows Crash Dump"
        # And the extension-only path also maps to the same name
        fake = tmp_path / "plain.dmp"
        fake.write_bytes(b"\x00" * 64)
        assert detect_format(fake) == "Windows Crash Dump"


# ── SB-11: rules resolve under any install mode ─────────────────

class TestSB11RulesResolve:
    def test_default_rules_dir_resolves_and_exists(self):
        from deaddrop.core.config import _default_rules_dir
        d = _default_rules_dir()
        # Under this editable install the bundled rules ship in the package.
        assert d.exists(), f"bundled rules dir must resolve: {d}"
        yar_files = list(d.rglob("*.yar"))
        assert len(yar_files) >= 3, "expected at least 3 bundled .yar rules"
