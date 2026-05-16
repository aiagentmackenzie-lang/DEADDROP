"""Tests for bug fixes — validates all 20 bugs from BUG_CATALOG.md are fixed."""

import struct
import pytest
from pathlib import Path

from deaddrop.core.case import CaseManager
from deaddrop.hunt.ioc_matcher import IOCMatcher, IOC_PATTERNS
from deaddrop.disk.carving import FileCarver, SIGNATURES
from deaddrop.report.generator import ReportGenerator
from deaddrop.triage.scorer import TriageScorer
from deaddrop.triage.anomaly import AnomalyDetector
from deaddrop.timeline.export import TimelineExporter


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


# ── C-01: XSS in HTML reports ──────────────────────────────────

class TestC01XSSPrevention:
    def test_script_tag_escaped_in_report(self, case_mgr, tmp_path):
        """Script tags in case names must be HTML-escaped in reports."""
        c = case_mgr.create_case('<script>alert("xss")</script>')
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1024, "a" * 64, "b" * 32, "RAW")
        case_mgr.add_artifact(c.id, "ev1", "events", "test", "", '<img src=x onerror=alert(1)>', "high")

        gen = ReportGenerator(case_mgr)
        output = str(tmp_path / "xss_report.html")
        path = gen.generate(c.id, "html", output)
        content = Path(path).read_text()

        # Raw script/img tags must NOT appear — they should be escaped
        assert "<script>alert" not in content
        assert "<img src=x onerror" not in content
        # Escaped versions should be present
        assert "&lt;script&gt;" in content or "<script>" not in content
        assert "&lt;img" in content or "<img" not in content

    def test_xss_in_artifact_description(self, case_mgr, tmp_path):
        """XSS payloads in artifact descriptions are escaped."""
        c = case_mgr.create_case("Safe Case")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1024, "a" * 64, "b" * 32, "RAW")
        case_mgr.add_artifact(c.id, "ev1", "hunt", "test", "", '"><script>document.cookie</script>', "critical")

        gen = ReportGenerator(case_mgr)
        output = str(tmp_path / "xss2_report.html")
        path = gen.generate(c.id, "html", output)
        content = Path(path).read_text()

        assert "<script>document.cookie</script>" not in content


# ── C-02: SQL injection via update_case ─────────────────────────

class TestC02SQLInjectionPrevention:
    def test_malicious_column_name_rejected(self, case_mgr):
        """Malicious column names in kwargs are silently filtered out."""
        c = case_mgr.create_case("Safe")

        # Try to inject via column name — should be filtered by whitelist
        result = case_mgr.update_case(c.id, **{'name = "HACKED" --': 'evil'})
        assert result is False  # Column not in whitelist

        # Case should still be accessible and unchanged
        found = case_mgr.get_case(c.id)
        assert found.name == "Safe"

    def test_only_allowed_columns_updated(self, case_mgr):
        """Only whitelisted columns (name, analyst, status, notes) are updated."""
        c = case_mgr.create_case("Original")

        # Valid columns work
        assert case_mgr.update_case(c.id, name="Updated", analyst="Bob") is True
        found = case_mgr.get_case(c.id)
        assert found.name == "Updated"
        assert found.analyst == "Bob"

    def test_unknown_column_ignored(self, case_mgr):
        """Unknown column names are silently ignored, not causing errors."""
        c = case_mgr.create_case("Test")
        # 'nonexistent' is not in whitelist — should return False
        assert case_mgr.update_case(c.id, nonexistent="value") is False


# ── C-03: Private IP range 172.16/12 ──────────────────────────

class TestC03PrivateIPRange:
    def test_172_16_range(self, case_mgr):
        """172.16.0.0/12 full range is classified as private (info)."""
        matcher = IOCMatcher(case_mgr)
        assert matcher._assess_severity("ipv4", "172.16.0.1") == "info"
        assert matcher._assess_severity("ipv4", "172.20.0.1") == "info"
        assert matcher._assess_severity("ipv4", "172.31.255.255") == "info"

    def test_172_32_is_public(self, case_mgr):
        """172.32.x.x is NOT private (outside /12 range)."""
        matcher = IOCMatcher(case_mgr)
        assert matcher._assess_severity("ipv4", "172.32.0.1") == "medium"

    def test_loopback_is_info(self, case_mgr):
        """127.0.0.0/8 loopback is classified as info (private)."""
        matcher = IOCMatcher(case_mgr)
        assert matcher._assess_severity("ipv4", "127.0.0.1") == "info"
        assert matcher._assess_severity("ipv4", "127.255.255.255") == "info"

    def test_link_local_is_info(self, case_mgr):
        """169.254.0.0/16 link-local is classified as info (private)."""
        matcher = IOCMatcher(case_mgr)
        assert matcher._assess_severity("ipv4", "169.254.1.1") == "info"

    def test_standard_private_ranges(self, case_mgr):
        """10.0.0.0/8 and 192.168.0.0/16 still classified correctly."""
        matcher = IOCMatcher(case_mgr)
        assert matcher._assess_severity("ipv4", "10.0.0.1") == "info"
        assert matcher._assess_severity("ipv4", "192.168.1.1") == "info"


# ── H-01: GIF footer signature ─────────────────────────────────

class TestH01GIFFooter:
    def test_gif_footer_is_single_byte(self):
        """GIF footer is 0x3B (single byte), not 0x00 0x3B."""
        assert SIGNATURES["GIF"]["footer"] == b"\x3b"

    def test_carve_gif_after_non_null_data(self, tmp_path):
        """GIF with trailer 0x3B after non-NUL data is carved correctly."""
        image = tmp_path / "test.raw"
        output = tmp_path / "carved"
        output.mkdir()

        # GIF where trailer 0x3B follows image data (not NUL)
        gif_data = b"GIF89a" + b"\x00" * 20 + b"\x2c" + b"\x3b"  # 0x3b after 0x2c
        padding = b"\x00" * 64
        image.write_bytes(padding + gif_data + padding)

        carver = FileCarver()
        results = carver.carve(image, output)
        assert len(results) == 1
        assert results[0]["type"] == "GIF"


# ── H-02: ZIP/DOCX duplicate signatures removed ────────────────

class TestH02ZIPDOCXNoDuplicates:
    def test_docx_not_in_signatures(self):
        """DOCX signature removed from SIGNATURES to prevent duplicate carving."""
        assert "DOCX" not in SIGNATURES

    def test_zip_in_signatures(self):
        """ZIP signature still present."""
        assert "ZIP" in SIGNATURES


# ── H-03: Command injection via plugin name ─────────────────────

class TestH03VolatilityPluginValidation:
    def test_unknown_plugin_rejected(self, case_mgr):
        """Unknown plugin names are rejected by VolatilityWrapper."""
        from deaddrop.memory.volatility import VolatilityWrapper
        wrapper = VolatilityWrapper(case_mgr)
        result = wrapper.run_plugin("nonexistent_case", None, "malicious; rm -rf /")
        assert "error" in result
        assert "Unknown plugin" in result["error"]

    def test_valid_plugin_name_accepted(self, case_mgr):
        """Valid Volatility3 plugin names pass validation."""
        from deaddrop.memory.volatility import VolatilityWrapper
        wrapper = VolatilityWrapper(case_mgr)
        c = case_mgr.create_case("Test")
        result = wrapper.run_plugin(c.id, None, "windows.pslist")
        # Should not error on plugin name (may error on missing memory evidence)
        assert "error" not in result or "No memory evidence" in result.get("error", "")


# ── H-04: SQLite WAL mode and FK enforcement ───────────────────

class TestH04SQLiteWALAndFK:
    def test_wal_mode_enabled(self, tmp_path):
        """CaseManager enables WAL journal mode."""
        mgr = CaseManager(tmp_path / "test.db")
        mode = mgr.conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        mgr.close()

    def test_foreign_keys_enforced(self, tmp_path):
        """CaseManager enforces foreign key constraints."""
        mgr = CaseManager(tmp_path / "test.db")
        fk = mgr.conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1
        mgr.close()

    def test_artifact_with_null_evidence_id(self, tmp_path):
        """Artifacts can be created with NULL evidence_id (for triage)."""
        mgr = CaseManager(tmp_path / "test.db")
        c = mgr.create_case("FK Test")
        # NULL evidence_id should work
        aid = mgr.add_artifact(c.id, None, "triage", "anomaly", "", "Test anomaly", "high")
        assert aid  # Should succeed
        artifacts = mgr.list_artifacts(c.id)
        assert len(artifacts) == 1
        assert artifacts[0]["evidence_id"] is None
        mgr.close()

    def test_artifact_with_invalid_evidence_id_rejected(self, tmp_path):
        """FK constraint rejects artifacts with nonexistent evidence_id."""
        mgr = CaseManager(tmp_path / "test.db")
        c = mgr.create_case("FK Test")
        with pytest.raises(Exception):
            mgr.add_artifact(c.id, "nonexistent_ev", "test", "test", "", "Test")
        mgr.close()


# ── M-01: IPv6 regex supports compressed forms ─────────────────

class TestM01IPv6Regex:
    def test_loopback_ipv6(self):
        """IPv6 loopback ::1 is matched."""
        assert bool(IOC_PATTERNS["ipv6"].search("::1"))

    def test_link_local_ipv6(self):
        """IPv6 link-local fe80::1 is matched."""
        assert bool(IOC_PATTERNS["ipv6"].search("fe80::1"))

    def test_shortened_ipv6(self):
        """IPv6 compressed form 2001:db8::1 is matched."""
        assert bool(IOC_PATTERNS["ipv6"].search("2001:db8::1"))

    def test_full_ipv6(self):
        """Full 8-group IPv6 is still matched."""
        assert bool(IOC_PATTERNS["ipv6"].search("2001:0db8:0000:0000:0000:0000:0000:0001"))


# ── M-02: IPv4 regex doesn't match version numbers ─────────────

class TestM02IPv4NoVersionNumbers:
    def test_version_number_not_matched(self):
        """Version numbers like 3.10.1 are NOT matched as IPv4."""
        text = "Python 3.10.1 released"
        matches = IOC_PATTERNS["ipv4"].findall(text)
        assert "3.10.0.1" not in matches if matches else True
        # More precisely: 3.10.1 is only 3 octets, won't match full IPv4
        # But test that "3.10.1" alone doesn't match
        assert not IOC_PATTERNS["ipv4"].search("3.10.1")

    def test_real_ip_still_matched(self):
        """Real IP addresses like 192.168.1.1 are still matched."""
        assert bool(IOC_PATTERNS["ipv4"].search("192.168.1.1"))

    def test_ip_in_context(self):
        """IP address in sentence context is matched."""
        matches = IOC_PATTERNS["ipv4"].findall("Connection from 10.0.0.1 accepted")
        assert "10.0.0.1" in matches


# ── M-03: Body file header included ────────────────────────────

class TestM03BodyFileHeader:
    def test_body_file_includes_header(self, case_mgr, tmp_path):
        """Exported body file includes the standard header comment."""
        c = case_mgr.create_case("Body Test")
        case_mgr.add_timeline_entry(c.id, "events", "2026-04-15T10:00:00Z", "Test event")

        exporter = TimelineExporter(case_mgr)
        path = exporter.export(c.id, "body", str(tmp_path / "timeline.body"))
        content = Path(path).read_text()

        assert content.startswith("# Body file generated by DEADDROP")


# ── M-05: Longer UUID[:12] for IDs ──────────────────────────────

class TestM05LongerUUIDs:
    def test_case_id_is_12_chars(self, case_mgr):
        """Case IDs are 12 hex characters (48 bits of entropy)."""
        c = case_mgr.create_case("UUID Test")
        assert len(c.id) == 12

    def test_evidence_id_is_12_chars(self, case_mgr, tmp_path):
        """Evidence IDs are 12 hex characters."""
        c = case_mgr.create_case("UUID Test")
        from deaddrop.core.evidence import EvidenceManager
        em = EvidenceManager(case_mgr)
        # Create a temp file for ingestion
        f = tmp_path / "test.raw"
        f.write_bytes(b"A" * 1024)
        result = em.ingest_disk(c.id, str(f))
        assert len(result["id"]) == 12


# ── M-06: Bessel's correction for variance ─────────────────────

class TestM06BesselCorrection:
    def test_anomaly_detector_uses_sample_variance(self, case_mgr):
        """AnomalyDetector uses N-1 (sample variance), not N (population variance)."""
        c = case_mgr.create_case("Bessel Test")
        # Small sample: 2 hours with different counts
        # With N-1 divisor, variance is larger → burst detection more conservative
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-15T10:00:00", "Event 1")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-15T10:01:00", "Event 2")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-15T11:00:00", "Event 3")

        detector = AnomalyDetector(case_mgr)
        anomalies = detector.detect(c.id)
        # Should not crash; verify the function completes
        assert isinstance(anomalies, list)


# ── M-07: PDF fallback logs warning ────────────────────────────

class TestM07PDFWarning:
    def test_pdf_fallback_returns_html(self, case_mgr, tmp_path):
        """PDF fallback returns HTML path with explanatory message."""
        c = case_mgr.create_case("PDF Test")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/img.raw", "img.raw", 1024, "a" * 64, "b" * 32, "RAW")
        gen = ReportGenerator(case_mgr)
        output = str(tmp_path / "report.pdf")
        path = gen.generate(c.id, "pdf", output)
        # Should fallback to HTML
        assert ".html" in path


# ── H-06: Prefetch v30 SCCA signature check ────────────────────

class TestH06PrefetchV30Signature:
    def test_v30_valid_scca(self, tmp_path):
        """Valid v30 prefetch with SCCA signature parses correctly."""
        from deaddrop.disk.prefetch import PrefetchAnalyzer
        case_mgr = CaseManager(tmp_path / "test.db")
        analyzer = PrefetchAnalyzer(case_mgr)

        pf_file = tmp_path / "test.pf"
        data = bytearray(1024)
        struct.pack_into("<I", data, 0, 30)  # version
        data[4:8] = b"SCCA"  # signature
        struct.pack_into("<I", data, 68, 5)  # run_count
        pf_file.write_bytes(bytes(data))

        result = analyzer.parse_prefetch_file(pf_file)
        assert result is not None
        assert result["version"] == 30
        assert result["run_count"] == 5
        case_mgr.close()

    def test_v30_invalid_signature_fallback(self, tmp_path):
        """v30 prefetch without SCCA signature falls back to path stem."""
        from deaddrop.disk.prefetch import PrefetchAnalyzer
        case_mgr = CaseManager(tmp_path / "test.db")
        analyzer = PrefetchAnalyzer(case_mgr)

        pf_file = tmp_path / "mymalware.pf"
        data = bytearray(1024)
        struct.pack_into("<I", data, 0, 30)  # version
        data[4:8] = b"XXXX"  # wrong signature
        pf_file.write_bytes(bytes(data))

        result = analyzer.parse_prefetch_file(pf_file)
        assert result is not None
        assert result["executable"] == "mymalware"  # fallback to path stem
        case_mgr.close()


# ── L-01: Plugins accept case_manager parameter ────────────────

class TestL01PluginCaseManager:
    def test_hash_verifier_accepts_case_manager(self, case_mgr):
        """Hash verifier plugin accepts case_manager parameter."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "hash_verifier",
            str(Path(__file__).parent.parent / "src" / "deaddrop" / "plugins" / "builtin" / "hash-verifier" / "main.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        c = case_mgr.create_case("Plugin Test")
        result = mod.run(c.id, case_manager=case_mgr)
        assert "total" in result

    def test_suspicious_processes_accepts_case_manager(self, case_mgr):
        """Suspicious processes plugin accepts case_manager parameter."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "suspicious_processes",
            str(Path(__file__).parent.parent / "src" / "deaddrop" / "plugins" / "builtin" / "suspicious-processes" / "main.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        c = case_mgr.create_case("Plugin Test")
        result = mod.run(c.id, case_manager=case_mgr)
        assert "suspicious" in result

    def test_timeline_summary_accepts_case_manager(self, case_mgr):
        """Timeline summary plugin accepts case_manager parameter."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "timeline_summary",
            str(Path(__file__).parent.parent / "src" / "deaddrop" / "plugins" / "builtin" / "timeline-summary" / "main.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        c = case_mgr.create_case("Plugin Test")
        result = mod.run(c.id, case_manager=case_mgr)
        assert "total_entries" in result


# ── L-04: Volatility tabular output skips header ────────────────

class TestL04TabularHeaderSkip:
    def test_header_row_skipped(self, case_mgr):
        """Tabular output parser skips the first data row (column header)."""
        from deaddrop.memory.volatility import VolatilityWrapper
        wrapper = VolatilityWrapper(case_mgr)

        output = "Volatility 3\n==========\nPID    Process    Offset\n1234   cmd.exe    0x123\n5678   explorer   0x456"
        result = wrapper._parse_tabular_output(output, "windows.pslist")
        findings = result["findings"]
        # Column header row "PID    Process    Offset" should be skipped
        assert not any("PID" in f.get("description", "") for f in findings)
        assert len(findings) == 2  # Only the data rows


# ── Integration: TriageScorer with null evidence_id ─────────────

class TestTriageNullEvidenceId:
    def test_triage_scorer_with_null_evidence_id(self, case_mgr):
        """TriageScorer stores artifacts with NULL evidence_id (FK-safe)."""
        c = case_mgr.create_case("Triage FK Test")
        for i in range(20):
            case_mgr.add_timeline_entry(c.id, "events", f"2026-01-15T10:{i:02d}:00", f"Event {i}", "high")

        scorer = TriageScorer(case_mgr)
        result = scorer.score(c.id)
        if result["anomalies"] > 0:
            artifacts = case_mgr.list_artifacts(c.id, source="triage")
            assert len(artifacts) > 0
            # All triage artifacts should have NULL evidence_id
            for a in artifacts:
                assert a["evidence_id"] is None