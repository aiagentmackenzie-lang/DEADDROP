"""Tests for hunt module."""

import pytest
import json
from pathlib import Path

from deaddrop.core.case import CaseManager
from deaddrop.hunt.ioc_matcher import IOCMatcher


@pytest.fixture
def case_mgr(tmp_path):
    mgr = CaseManager(tmp_path / "test.db")
    yield mgr
    mgr.close()


class TestIOCMatcher:
    def test_parse_ioc_list(self, case_mgr):
        matcher = IOCMatcher(case_mgr)
        iocs = matcher._parse_iocs([
            {"type": "ipv4", "value": "1.2.3.4"},
            {"type": "domain", "value": "evil.com"},
        ])
        assert "ipv4" in iocs
        assert "domain" in iocs
        assert "1.2.3.4" in iocs["ipv4"]

    def test_severity_assessment(self, case_mgr):
        matcher = IOCMatcher(case_mgr)
        assert matcher._assess_severity("sha256", "abc") == "high"
        assert matcher._assess_severity("cve", "CVE-2026-0001") == "high"
        assert matcher._assess_severity("domain", "evil.ru") == "high"
        assert matcher._assess_severity("domain", "normal.com") == "medium"
        assert matcher._assess_severity("ipv4", "192.168.1.1") == "info"

    def test_match_ioc_file(self, case_mgr, tmp_path):
        case = case_mgr.create_case("Test")
        # Create IOC file
        ioc_file = tmp_path / "iocs.json"
        ioc_file.write_text(json.dumps([
            {"type": "ipv4", "value": "10.0.0.1"},
            {"type": "domain", "value": "evil.example.com"},
        ]))
        matcher = IOCMatcher(case_mgr)
        result = matcher.match(case.id, str(ioc_file))
        assert result["hits"] == 2