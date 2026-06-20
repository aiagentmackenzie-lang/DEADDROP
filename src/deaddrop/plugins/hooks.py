"""Plugin hook definitions — pipeline stages for plugin integration."""

from typing import ClassVar


class PipelineHooks:
    """Hook points in the DEADDROP processing pipeline."""

    PRE_INGEST = "pre_ingest"
    POST_INGEST = "post_ingest"
    PRE_ANALYZE = "pre_analyze"
    POST_ANALYZE = "post_analyze"
    PRE_HUNT = "pre_hunt"
    POST_HUNT = "post_hunt"
    PRE_REPORT = "pre_report"
    POST_REPORT = "post_report"
    CUSTOM = "custom"

    ALL_HOOKS: ClassVar[list[str]] = [
        PRE_INGEST, POST_INGEST,
        PRE_ANALYZE, POST_ANALYZE,
        PRE_HUNT, POST_HUNT,
        PRE_REPORT, POST_REPORT,
        CUSTOM,
    ]


def run_hooks(hook_name: str, plugins: dict, case_id: str, **context) -> dict:
    """Run all plugins registered for a specific hook point."""
    results: dict[str, dict] = {}
    for name, plugin in plugins.items():
        if hook_name in plugin.hooks:
            try:
                result = plugin.entry_point(case_id, **context)
                results[name] = result
            except Exception as e:
                results[name] = {"error": str(e)}
    return results
