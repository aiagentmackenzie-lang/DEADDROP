"""Tests for evidence manager."""

import pytest
import tempfile
from pathlib import Path

from deaddrop.core.case import CaseManager
from deaddrop.core.evidence import EvidenceManager, compute_hashes, detect_format, verify_integrity


@pytest.fixture
def tmp_db(tmp_path):
    return tmp_path / "test_cases.db"


@pytest.fixture
def case_mgr(tmp_db):
    mgr = CaseManager(tmp_db)
    yield mgr
    mgr.close()


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "test.raw"
    f.write_bytes(b"A" * 1024)
    return f


class TestHashVerification:
    def test_compute_hashes(self, sample_file):
        sha256, md5 = compute_hashes(sample_file)
        assert len(sha256) == 64
        assert len(md5) == 32
        # Same file should produce same hashes
        sha256_2, md5_2 = compute_hashes(sample_file)
        assert sha256 == sha256_2
        assert md5 == md5_2

    def test_different_files_different_hashes(self, tmp_path):
        f1 = tmp_path / "file1.raw"
        f2 = tmp_path / "file2.raw"
        f1.write_bytes(b"A" * 1024)
        f2.write_bytes(b"B" * 1024)
        sha1, _ = compute_hashes(f1)
        sha2, _ = compute_hashes(f2)
        assert sha1 != sha2

    def test_verify_integrity(self, sample_file):
        sha256, md5 = compute_hashes(sample_file)
        assert verify_integrity(sample_file, sha256) is True
        assert verify_integrity(sample_file, "0" * 64) is False


class TestFormatDetection:
    def test_raw_format(self, tmp_path):
        f = tmp_path / "image.raw"
        f.write_bytes(b"\x00" * 1024)
        assert detect_format(f) == "RAW"

    def test_e01_format(self, tmp_path):
        f = tmp_path / "image.E01"
        f.write_bytes(b"\x00" * 1024)
        assert detect_format(f) == "E01"

    def test_unknown_format(self, tmp_path):
        f = tmp_path / "image.xyz"
        f.write_bytes(b"\x00" * 1024)
        assert detect_format(f) == "UNKNOWN"


class TestEvidenceIngestion:
    def test_ingest_disk(self, case_mgr, sample_file):
        case = case_mgr.create_case("Test Case", analyst="Tester")
        em = EvidenceManager(case_mgr)
        result = em.ingest_disk(case.id, str(sample_file))
        assert result["type"] == "disk"
        assert result["sha256"]
        assert result["md5"]
        assert result["verified"] is True

    def test_ingest_memory(self, case_mgr, sample_file):
        case = case_mgr.create_case("Test Case", analyst="Tester")
        em = EvidenceManager(case_mgr)
        result = em.ingest_memory(case.id, str(sample_file))
        assert result["type"] == "memory"
        assert result["verified"] is True

    def test_ingest_nonexistent_file(self, case_mgr):
        case = case_mgr.create_case("Test Case")
        em = EvidenceManager(case_mgr)
        with pytest.raises(FileNotFoundError):
            em.ingest_disk(case.id, "/nonexistent/file.raw")

    def test_verify_evidence(self, case_mgr, sample_file):
        case = case_mgr.create_case("Test Case")
        em = EvidenceManager(case_mgr)
        em.ingest_disk(case.id, str(sample_file))
        evidence = case_mgr.list_evidence(case.id)
        assert len(evidence) == 1
        result = em.verify_evidence(case.id, evidence[0]["id"])
        assert result["verified"] is True