"""Plugin manager — load, list, and run DEADDROP plugins."""

import importlib
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Callable

from deaddrop.core.config import Config


@dataclass
class Plugin:
    name: str
    version: str
    description: str
    hooks: list[str]
    entry_point: Callable


# Plugin hook points (pipeline stages)
HOOK_POINTS = [
    "pre_ingest",       # Before evidence ingestion
    "post_ingest",      # After evidence ingestion
    "pre_analyze",      # Before analysis
    "post_analyze",     # After analysis
    "pre_hunt",         # Before hunting
    "post_hunt",        # After hunting
    "pre_report",       # Before report generation
    "post_report",      # After report generation
    "custom",           # Custom plugin entry
]


class PluginManager:
    """Manage DEADDROP plugins — load, list, run."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.plugins: dict[str, Plugin] = {}
        self._load_builtin_plugins()
        self._load_user_plugins()

    def list_plugins(self) -> list[dict]:
        """List all available plugins."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "hooks": p.hooks,
            }
            for p in self.plugins.values()
        ]

    def run_plugin(self, name: str, case_id: str, **kwargs) -> dict:
        """Run a specific plugin."""
        if name not in self.plugins:
            return {"error": f"Plugin '{name}' not found"}

        plugin = self.plugins[name]
        try:
            result = plugin.entry_point(case_id, **kwargs)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _load_builtin_plugins(self) -> None:
        """Load built-in plugins."""
        builtin_dir = Path(__file__).parent / "builtin"
        if not builtin_dir.exists():
            return

        for plugin_dir in builtin_dir.iterdir():
            if plugin_dir.is_dir() and (plugin_dir / "plugin.json").exists():
                self._load_plugin_from_dir(plugin_dir)

    def _load_user_plugins(self) -> None:
        """Load user-installed plugins."""
        user_dir = self.config.plugins_dir
        if not user_dir.exists():
            return

        for plugin_dir in user_dir.iterdir():
            if plugin_dir.is_dir() and (plugin_dir / "plugin.json").exists():
                self._load_plugin_from_dir(plugin_dir)

    def _load_plugin_from_dir(self, plugin_dir: Path) -> None:
        """Load a plugin from a directory containing plugin.json."""
        try:
            manifest = json.loads((plugin_dir / "plugin.json").read_text())
            name = manifest.get("name", plugin_dir.name)
            version = manifest.get("version", "1.0.0")
            description = manifest.get("description", "")
            hooks = manifest.get("hooks", ["custom"])

            # Try to load the entry point module
            entry_module = manifest.get("entry", "main")
            entry_file = plugin_dir / f"{entry_module}.py"

            if entry_file.exists():
                # Dynamic import
                spec = importlib.util.spec_from_file_location(
                    f"deaddrop_plugin_{name}", str(entry_file)
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    entry_point = getattr(module, "run", lambda case_id, **kw: {"status": "ok"})
                else:
                    def entry_point(case_id, **kw):  # type: ignore[misc]
                        return {"status": "no_entry"}
            else:
                def entry_point(case_id, **kw):  # type: ignore[misc]
                    return {"status": "no_file"}

            self.plugins[name] = Plugin(
                name=name,
                version=version,
                description=description,
                hooks=hooks,
                entry_point=entry_point,
            )
        except (json.JSONDecodeError, OSError, ImportError):
            pass