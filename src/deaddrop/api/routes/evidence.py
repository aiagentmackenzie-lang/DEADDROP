"""Evidence ingestion routes — in-process, no subprocess."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from deaddrop.api import events
from deaddrop.api.deps import AuthDep, CaseMgrDep
from deaddrop.api.models import DiskIngest, MemoryIngest
from deaddrop.core.evidence import EvidenceManager

router = APIRouter()


@router.post("/disk", status_code=status.HTTP_201_CREATED)
def ingest_disk(mgr: CaseMgrDep, _: AuthDep, body: DiskIngest) -> dict:
    if not mgr.get_case(body.case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {body.case_id} not found")
    em = EvidenceManager(mgr)
    try:
        result = em.ingest_disk(body.case_id, body.image_path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    events.emit("evidence.ingested", {"case_id": body.case_id, "evidence_id": result["id"], "type": "disk"})
    return result


@router.post("/memory", status_code=status.HTTP_201_CREATED)
def ingest_memory(mgr: CaseMgrDep, _: AuthDep, body: MemoryIngest) -> dict:
    if not mgr.get_case(body.case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {body.case_id} not found")
    em = EvidenceManager(mgr)
    try:
        result = em.ingest_memory(body.case_id, body.dump_path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    events.emit("evidence.ingested", {"case_id": body.case_id, "evidence_id": result["id"], "type": "memory"})
    return result


@router.post("/{case_id}/{evidence_id}/verify")
def verify_evidence(mgr: CaseMgrDep, _: AuthDep, case_id: str, evidence_id: str) -> dict:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    em = EvidenceManager(mgr)
    result = em.verify_evidence(case_id, evidence_id)
    if not result["verified"] and result.get("reason") == "Evidence not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    return result
