# DEADDROP Plugin Development Guide

## Creating a Plugin

1. Create a directory in `~/.deaddrop/plugins/` (user) or
   `src/deaddrop/plugins/builtin/` (built-in).

2. Create `plugin.json`:

```json
{
    "name": "my-plugin",
    "version": "1.0.0",
    "description": "What it does",
    "hooks": ["post_analyze", "custom"],
    "entry": "main"
}
```

3. Create `main.py`:

```python
def run(case_id: str, **kwargs) -> dict:
    """Plugin entry point. Receives case_id and optional kwargs.

    When run via `deaddrop plugin run`, a `case_manager` keyword argument is
    injected so the plugin can access the case's CaseManager without creating
    its own connection.
    """
    case_manager = kwargs.get("case_manager")
    if case_manager is None:
        from deaddrop.core.config import Config
        from deaddrop.core.case import CaseManager
        case_manager = CaseManager(Config.load().db_path)
    case = case_manager.get_case(case_id)
    evidence = case_manager.list_evidence(case_id)
    return {"status": "ok", "findings": len(evidence)}
```

## Running Plugins

```bash
deaddrop plugin list
deaddrop plugin run my-plugin --case <case-id>
```

## Hook Points

| Hook | When | Context |
|------|------|---------|
| `pre_ingest` | Before evidence ingestion | evidence_path |
| `post_ingest` | After evidence ingestion | evidence_id, hashes |
| `pre_analyze` | Before analysis | evidence_id |
| `post_analyze` | After analysis | artifact_count |
| `pre_hunt` | Before hunting | rules_path |
| `post_hunt` | After hunting | hits |
| `pre_report` | Before report generation | format |
| `post_report` | After report generation | output_path |
| `custom` | Manual trigger | any |

> **Note (honest):** `run_hooks()` is defined in `plugins/hooks.py` but **no CLI
> command invokes it automatically** in v1.2.0. Hooks are a documented extension
> point for custom integrations; the built-in pipeline does not fire them. Run
> plugins explicitly with `deaddrop plugin run`.

## ⚠️ Security: Plugins Are Trusted

Plugins are loaded via `importlib.util.spec_from_file_location` and
`exec_module` — they run **in the same Python process** as the engine with full
access to the filesystem, network, and the `CaseManager`. **There is no
sandbox.** Only load plugins from sources you trust. (The previous README
claimed "plugin sandboxing" that did not exist; that claim was removed.)