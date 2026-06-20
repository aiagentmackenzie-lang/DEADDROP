"""Phase 4 regression tests — audit logging, integrity gate, fail-closed update."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from deaddrop.core.case import CaseManager


@pytest.fixture
def case_mgr(tmp_path, monkeypatch):
    """Isolate audit log + DB to tmp_path."""
    monkeypatch.setenv("DEADDROP_HOME", str(tmp_path))
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


class TestAuditLog:
    def test_create_case_writes_audit_record(self, case_mgr, tmp_path):
        from deaddrop.core.audit import _audit_log_path, verify_audit_log
        c = case_mgr.create_case("Audit Test", analyst="alice")
        log_path = _audit_log_path()
        assert log_path.exists()
        content = log_path.read_text()
        assert "case.create" in content
        assert c.id in content
        assert "alice" in content
        # Hash chain is valid
        v = verify_audit_log(log_path)
        assert v["valid"] is True
        assert v["entries"] >= 1

    def test_every_mutation_is_audited(self, case_mgr):
        from deaddrop.core.audit import _audit_log_path
        c = case_mgr.create_case("All Mutations")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/x", "x", 1, "a" * 64, "b" * 32, "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "d")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01", "e")
        case_mgr.add_hunt_result(c.id, "hr1", "rule1", "yara")
        case_mgr.update_case(c.id, notes="updated note")
        case_mgr.close_case(c.id)
        case_mgr.delete_case(c.id)
        content = _audit_log_path().read_text()
        for action in ("case.create", "evidence.add", "artifact.add", "timeline.add",
                       "hunt.add", "case.update", "case.close", "case.delete"):
            assert action in content, f"audit log missing {action}"

    def test_tamper_detection_breaks_chain(self, case_mgr, tmp_path):
        """Appending a forged line or editing a hash makes verify_audit_log fail."""
        from deaddrop.core.audit import _audit_log_path, verify_audit_log
        case_mgr.create_case("Tamper Test")
        log = _audit_log_path()
        # Corrupt the hash of the first entry
        lines = log.read_text().splitlines()
        import json
        rec = json.loads(lines[0])
        rec["hash"] = "0" * 64
        lines[0] = json.dumps(rec)
        log.write_text("\n".join(lines) + "\n")
        v = verify_audit_log(log)
        assert v["valid"] is False


class TestUpdateCaseFailClosed:
    def test_unknown_column_rejected_and_logged(self, case_mgr, caplog):
        c = case_mgr.create_case("Fail Closed Test")
        with caplog.at_level(logging.WARNING, logger="deaddrop.core.case"):
            ok = case_mgr.update_case(c.id, name="ok", bogus="evil")
        # A mix of valid + unknown is rejected entirely (fail-closed)
        assert ok is False
        assert any("unknown columns" in r.getMessage() for r in caplog.records)
        # Case name unchanged
        assert case_mgr.get_case(c.id).name == "Fail Closed Test"

    def test_pure_unknown_rejected(self, case_mgr):
        c = case_mgr.create_case("Pure Unknown")
        assert case_mgr.update_case(c.id, totallyfake="x") is False

    def test_only_valid_columns_update(self, case_mgr):
        c = case_mgr.create_case("Valid Update")
        assert case_mgr.update_case(c.id, name="New", notes="n") is True
        found = case_mgr.get_case(c.id)
        assert found.name == "New"
        assert found.notes == "n"


class TestReportIntegrityGate:
    def test_report_refuses_missing_evidence(self, case_mgr):
        """A report against evidence whose file is gone must be refused."""
        from deaddrop.report.generator import ReportGenerator
        c = case_mgr.create_case("Missing Ev Report")
        case_mgr.add_evidence(c.id, "ev1", "disk", "/tmp/does-not-exist-xyz.raw",
                              "ghost.raw", 1024, "a" * 64, "b" * 32, "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "d", "high")
        gen = ReportGenerator(case_mgr)
        with pytest.raises(ValueError, match="chain-of-custody"):
            gen.generate(c.id, "html")  # no skip_verify → must refuse

    def test_report_refuses_tampered_evidence(self, case_mgr, tmp_path):
        """A report against evidence whose hash changed must be refused."""
        from deaddrop.core.evidence import compute_hashes
        from deaddrop.report.generator import ReportGenerator
        f = tmp_path / "ev.raw"
        f.write_bytes(b"original content")
        h = compute_hashes(f)
        c = case_mgr.create_case("Tampered Ev Report")
        case_mgr.add_evidence(c.id, "ev1", "disk", str(f), "ev.raw",
                              f.stat().st_size, h[0], h[1], "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "d", "high")
        # Tamper with the file after ingestion
        f.write_bytes(b"TAMPERED DIFFERENT CONTENT")
        gen = ReportGenerator(case_mgr)
        with pytest.raises(ValueError, match="chain-of-custody"):
            gen.generate(c.id, "html")

    def test_skip_verify_overrides_gate(self, case_mgr, tmp_path):
        """skip_verify=True lets a report render despite missing evidence
        (explicit analyst sign-off)."""
        from deaddrop.report.generator import ReportGenerator
        c = case_mgr.create_case("Skip Verify Report")
        f = tmp_path / "ev.raw"
        f.write_bytes(b"\x00" * 64)
        from deaddrop.core.evidence import compute_hashes
        h = compute_hashes(f)
        case_mgr.add_evidence(c.id, "ev1", "disk", str(f), "ev.raw", 64, h[0], h[1], "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "d", "high")
        f.unlink()  # now missing
        gen = ReportGenerator(case_mgr)
        path = gen.generate(c.id, "html", skip_verify=True)
        assert Path(path).exists()

    def test_report_generates_when_evidence_intact(self, case_mgr, tmp_path):
        """Happy path: intact evidence → report generates without skip_verify."""
        from deaddrop.core.evidence import compute_hashes
        from deaddrop.report.generator import ReportGenerator
        f = tmp_path / "ev.raw"
        f.write_bytes(b"\x00" * 64)
        h = compute_hashes(f)
        c = case_mgr.create_case("Intact Ev Report")
        case_mgr.add_evidence(c.id, "ev1", "disk", str(f), "ev.raw", 64, h[0], h[1], "RAW")
        case_mgr.add_artifact(c.id, "ev1", "filesystem", "file", "2026-01-01", "d", "high")
        path = ReportGenerator(case_mgr).generate(c.id, "html")
        assert Path(path).exists()
