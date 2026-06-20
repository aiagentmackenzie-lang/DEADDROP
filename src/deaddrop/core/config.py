"""Configuration management."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


def _deaddrop_home() -> Path:
    """Resolve the DEADDROP home directory.

    Honors the DEADDROP_HOME env var (test/operator isolation) over Path.home().
    """
    env = os.environ.get("DEADDROP_HOME")
    if env:
        return Path(env)
    return Path.home()


DEFAULT_DB_PATH = _deaddrop_home() / ".deaddrop" / "cases.db"
DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent.parent / "rules"
DEFAULT_PLUGINS_DIR = _deaddrop_home() / ".deaddrop" / "plugins"


@dataclass
class Config:
    db_path: Path = DEFAULT_DB_PATH
    rules_dir: Path = DEFAULT_RULES_DIR
    plugins_dir: Path = DEFAULT_PLUGINS_DIR
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    server_host: str = "127.0.0.1"
    server_port: int = 8080

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        if path and path.exists():
            data = json.loads(path.read_text())
            return cls(
                db_path=Path(data.get("db_path", str(DEFAULT_DB_PATH))),
                rules_dir=Path(data.get("rules_dir", str(DEFAULT_RULES_DIR))),
                plugins_dir=Path(data.get("plugins_dir", str(DEFAULT_PLUGINS_DIR))),
                ollama_url=data.get("ollama_url", "http://localhost:11434"),
                ollama_model=data.get("ollama_model", "llama3"),
                server_host=data.get("server_host", "127.0.0.1"),
                server_port=data.get("server_port", 8080),
            )
        # Resolve defaults fresh from env (DEADDROP_HOME) at call time so test
        # isolation via monkeypatch.setenv actually takes effect.
        return cls(
            db_path=_deaddrop_home() / ".deaddrop" / "cases.db",
            rules_dir=DEFAULT_RULES_DIR,
            plugins_dir=_deaddrop_home() / ".deaddrop" / "plugins",
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "db_path": str(self.db_path),
            "rules_dir": str(self.rules_dir),
            "plugins_dir": str(self.plugins_dir),
            "ollama_url": self.ollama_url,
            "ollama_model": self.ollama_model,
            "server_host": self.server_host,
            "server_port": self.server_port,
        }, indent=2))

    def ensure_dirs(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
