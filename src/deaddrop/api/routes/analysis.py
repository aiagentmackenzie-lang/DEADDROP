"""Analysis routes — disk/memory/event/registry/prefetch/filesystem + triage."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from deaddrop.api import events
from deaddrop.api.deps import AuthDep, CaseMgrDep
from deaddrop.api.models import (
    AnalyzeRequest,
    EventAnalyzeRequest,
    MemoryAnalyzeRequest,
    TriageRequest,
)

router = APIRouter()


def _require_case(mgr, case_id: str) -> None:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")


@router.post("/filesystem")
def analyze_filesystem(mgr: CaseMgrDep, _: AuthDep, body: AnalyzeRequest) -> dict:
    from deaddrop.disk.filesystem import FilesystemAnalyzer
    _require_case(mgr, body.case_id)
    results = FilesystemAnalyzer(mgr).analyze(body.case_id, body.evidence_id)
    events.emit("analyze.filesystem", {"case_id": body.case_id, "results": results})
    return results


@router.post("/registry")
def analyze_registry(mgr: CaseMgrDep, _: AuthDep, body: AnalyzeRequest) -> dict:
    from deaddrop.disk.registry import RegistryAnalyzer
    _require_case(mgr, body.case_id)
    results = RegistryAnalyzer(mgr).analyze(body.case_id, body.evidence_id)
    events.emit("analyze.registry", {"case_id": body.case_id, "results": results})
    return results


@router.post("/prefetch")
def analyze_prefetch(mgr: CaseMgrDep, _: AuthDep, body: AnalyzeRequest) -> dict:
    from deaddrop.disk.prefetch import PrefetchAnalyzer
    _require_case(mgr, body.case_id)
    results = PrefetchAnalyzer(mgr).analyze(body.case_id, body.evidence_id)
    events.emit("analyze.prefetch", {"case_id": body.case_id, "results": results})
    return results


@router.post("/events")
def analyze_events(mgr: CaseMgrDep, _: AuthDep, body: EventAnalyzeRequest) -> dict:
    from deaddrop.disk.events import EventLogAnalyzer
    _require_case(mgr, body.case_id)
    results = EventLogAnalyzer(mgr).analyze(body.case_id, body.evidence_id, body.source)
    events.emit("analyze.events", {"case_id": body.case_id, "results": results})
    return results


@router.post("/memory")
def analyze_memory(mgr: CaseMgrDep, _: AuthDep, body: MemoryAnalyzeRequest) -> dict:
    from deaddrop.memory.volatility import VolatilityWrapper
    _require_case(mgr, body.case_id)
    results = VolatilityWrapper(mgr).run_plugin(body.case_id, body.evidence_id, body.plugin)
    events.emit("analyze.memory", {"case_id": body.case_id, "plugin": body.plugin, "results": results})
    return results


@router.post("/timeline/generate")
def generate_timeline(mgr: CaseMgrDep, _: AuthDep, body: TriageRequest) -> dict:
    from deaddrop.timeline.engine import TimelineEngine
    _require_case(mgr, body.case_id)
    results = TimelineEngine(mgr).generate(body.case_id)
    events.emit("timeline.generated", {"case_id": body.case_id, "results": results})
    return results


@router.post("/triage")
def triage_run(mgr: CaseMgrDep, _: AuthDep, body: TriageRequest) -> dict:
    from deaddrop.triage.scorer import TriageScorer
    _require_case(mgr, body.case_id)
    results = TriageScorer(mgr).score(body.case_id)
    events.emit("triage.completed", {"case_id": body.case_id, "results": results})
    return results


@router.post("/triage/summary")
def triage_summary(mgr: CaseMgrDep, _: AuthDep, body: TriageRequest) -> dict:
    from deaddrop.triage.llm import LLMSummarizer
    _require_case(mgr, body.case_id)
    summary = LLMSummarizer(mgr).summarize(body.case_id)
    return {"summary": summary}
