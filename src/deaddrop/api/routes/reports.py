"""Report + timeline export routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse

from deaddrop.api import events
from deaddrop.api.deps import AuthDep, CaseMgrDep
from deaddrop.api.models import ReportRequest, TimelineExportRequest

router = APIRouter()


@router.post("/generate")
def generate_report(mgr: CaseMgrDep, _: AuthDep, body: ReportRequest) -> dict:
    from deaddrop.report.generator import ReportGenerator
    if not mgr.get_case(body.case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {body.case_id} not found")
    gen = ReportGenerator(mgr)
    try:
        path = gen.generate(body.case_id, body.format, body.output_path)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    # The generator may append a note to the path when falling back to HTML
    actual_path = path.split(" ")[0]
    events.emit("report.generated", {"case_id": body.case_id, "format": body.format, "path": actual_path})
    return {"path": path, "format": body.format}


@router.post("/timeline/export")
def export_timeline(mgr: CaseMgrDep, _: AuthDep, body: TimelineExportRequest) -> dict:
    from deaddrop.timeline.export import TimelineExporter
    if not mgr.get_case(body.case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {body.case_id} not found")
    exporter = TimelineExporter(mgr)
    path = exporter.export(body.case_id, body.format, body.output_path)
    return {"path": path, "format": body.format}


@router.get("/timeline/{case_id}/export", response_model=None)
def export_timeline_get(mgr: CaseMgrDep, _: AuthDep, case_id: str, format: str = "csv") -> FileResponse | PlainTextResponse:
    """Export timeline and stream the file back to the client."""
    from deaddrop.timeline.export import TimelineExporter
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    if format not in ("csv", "json", "body"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="format must be csv|json|body")
    exporter = TimelineExporter(mgr)
    path = exporter.export(case_id, format)
    p = Path(path)
    media_types = {"csv": "text/csv", "json": "application/json", "body": "text/plain"}
    return FileResponse(str(p), media_type=media_types[format], filename=p.name)
