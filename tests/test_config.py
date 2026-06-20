"""Tests for Config management."""

import json
from pathlib import Path

from deaddrop.core.config import Config


class TestConfig:
    def test_default_config(self):
        """Config defaults are populated."""
        cfg = Config()
        assert cfg.ollama_url == "http://localhost:11434"
        assert cfg.ollama_model == "llama3"
        assert cfg.server_host == "127.0.0.1"
        assert cfg.server_port == 8080

    def test_load_from_file(self, tmp_path):
        """Config loads from JSON file."""
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text(json.dumps({
            "ollama_url": "http://custom:11434",
            "ollama_model": "mistral",
            "server_port": 9090,
        }))
        cfg = Config.load(cfg_file)
        assert cfg.ollama_url == "http://custom:11434"
        assert cfg.ollama_model == "mistral"
        assert cfg.server_port == 9090
        # Defaults preserved for missing keys
        assert cfg.server_host == "127.0.0.1"

    def test_load_nonexistent_file(self):
        """Loading from nonexistent path returns defaults."""
        cfg = Config.load(Path("/nonexistent/config.json"))
        assert cfg.ollama_model == "llama3"

    def test_save_and_reload(self, tmp_path):
        """Config round-trips through save/load."""
        cfg_file = tmp_path / "config.json"
        cfg = Config(
            ollama_model="codellama",
            server_port=3000,
        )
        cfg.save(cfg_file)

        loaded = Config.load(cfg_file)
        assert loaded.ollama_model == "codellama"
        assert loaded.server_port == 3000

    def test_ensure_dirs_creates_directories(self, tmp_path):
        """ensure_dirs creates the db and plugins directories."""
        cfg = Config(
            db_path=tmp_path / "deep" / "nested" / "cases.db",
            plugins_dir=tmp_path / "plugins",
        )
        cfg.ensure_dirs()
        assert (tmp_path / "deep" / "nested").exists()
        assert (tmp_path / "plugins").exists()
