"""Tests for the plugin manager — regression guard for SB-1.

SB-1 (2026-05-16 audit miss): `plugins/manager.py` used `importlib.util` without
`import importlib.util`, so `deaddrop plugin list` crashed with
`AttributeError: module 'importlib' has no attribute 'util'`. These tests
instantiate the manager and run a built-in plugin so the regression can't
recurcur silently.
"""

from pathlib import Path

import pytest

from deaddrop.core.case import CaseManager
from deaddrop.core.config import Config
from deaddrop.plugins.manager import PluginManager


@pytest.fixture
def case_mgr(tmp_path):
    db = tmp_path / "test.db"
    mgr = CaseManager(db)
    yield mgr
    mgr.close()


@pytest.fixture
def config(tmp_path, monkeypatch):
    """Config pointing at a tmp plugins dir so user plugins don't leak in."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    cfg = Config.load()
    cfg.ensure_dirs()
    return cfg


class TestPluginManagerLoad:
    def test_manager_constructs_without_crash(self, config):
        """SB-1 regression: PluginManager() must not raise AttributeError."""
        pm = PluginManager(config)
        # Built-in plugins should be discovered
        names = {p["name"] for p in pm.list_plugins()}
        assert "hash-verifier" in names
        assert "suspicious-processes" in names
        assert "timeline-summary" in names

    def test_list_plugins_returns_manifest_fields(self, config):
        pm = PluginManager(config)
        plugins = pm.list_plugins()
        assert len(plugins) >= 3
        for p in plugins:
            assert "name" in p
            assert "version" in p
            assert "description" in p
            assert "hooks" in p
            assert isinstance(p["hooks"], list)

    def test_run_unknown_plugin_returns_error(self, config, case_mgr):
        pm = PluginManager(config)
        c = case_mgr.create_case("Plugin Err Test")
        result = pm.run_plugin("does-not-exist", c.id)
        assert result["success"] is False
        assert "not found" in result["error"]


class TestBuiltinPluginHashVerifier:
    def test_hash_verifier_runs_with_case_manager(self, config, case_mgr):
        """Builtin hash-verifier accepts an injected CaseManager (L-01 fix)."""
        pm = PluginManager(config)
        c = case_mgr.create_case("Hash Verifier Test")
        result = pm.run_plugin("hash-verifier", c.id, case_manager=case_mgr)
        assert result["success"] is True
        assert "total" in result["result"]
        assert "verified" in result["result"]

    def test_hash_verifier_detects_missing_file(self, config, case_mgr, tmp_path):
        """Re-verification flags evidence whose backing file is gone."""
        pm = PluginManager(config)
        c = case_mgr.create_case("Missing Evidence Test")
        # Register evidence pointing at a path that doesn't exist
        case_mgr.add_evidence(
            c.id, "ev-missing", "disk", str(tmp_path / "ghost.raw"),
            "ghost.raw", 1024, "a" * 64, "b" * 32, "RAW",
        )
        result = pm.run_plugin("hash-verifier", c.id, case_manager=case_mgr)
        assert result["success"] is True
        res = result["result"]
        assert res["total"] >= 1
        # The missing file should be counted as missing
        assert res.get("missing", 0) >= 1


class TestBuiltinPluginTimelineSummary:
    def test_timeline_summary_runs(self, config, case_mgr):
        pm = PluginManager(config)
        c = case_mgr.create_case("Timeline Summary Test")
        case_mgr.add_timeline_entry(c.id, "events", "2026-01-01T00:00:00", "logon", "info")
        case_mgr.add_timeline_entry(c.id, "memory", "2026-01-01T01:00:00", "proc", "high")
        result = pm.run_plugin("timeline-summary", c.id, case_manager=case_mgr)
        assert result["success"] is True
