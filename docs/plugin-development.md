# Plugin Development Guide

## Creating a Plugin

1. Create a directory in `~/.deaddrop/plugins/` or `src/deaddrop/plugins/builtin/`

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
    """Plugin entry point. Receives case_id and optional kwargs."""
    # Your logic here
    return {"status": "ok", "findings": 0}
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

## Using the CaseManager

```python
from deaddrop.core.case import CaseManager
from deaddrop.core.config import Config

def run(case_id: str, **kwargs):
    config = Config.load()
    mgr = CaseManager(config.db_path)
    
    # Access case data
    case = mgr.get_case(case_id)
    evidence = mgr.list_evidence(case_id)
    artifacts = mgr.list_artifacts(case_id)
    
    # Add findings
    mgr.add_artifact(case_id, evidence_id="", source="my-plugin",
                      category="custom", timestamp="", description="Found something",
                      severity="medium")
    
    mgr.close()
    return {"findings": 1}
```