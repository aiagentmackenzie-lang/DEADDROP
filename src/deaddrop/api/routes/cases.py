"""Case routes — CRUD + close/update, in-process (no subprocess bridge)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from deaddrop.api import events
from deaddrop.api.deps import AuthDep, CaseMgrDep
from deaddrop.api.models import CaseCreate, CaseUpdate
from deaddrop.core.evidence import EvidenceManager

router = APIRouter()


@router.get("/")
def list_cases(mgr: CaseMgrDep, _: AuthDep, status_filter: str | None = None) -> dict:
    """List all cases, optionally filtered by status (open/closed/archived)."""
    return {"cases": [c.to_dict() for c in mgr.list_cases(status_filter)]}


@router.get("/{case_id}")
def get_case(mgr: CaseMgrDep, _: AuthDep, case_id: str) -> dict:
    case = mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    evidence = mgr.list_evidence(case_id)
    artifacts = mgr.list_artifacts(case_id)
    timeline = mgr.get_timeline(case_id)
    hunt_results = mgr.get_hunt_results(case_id)
    return {
        **case.to_dict(),
        "evidence": evidence,
        "evidence_count": len(evidence),
        "artifact_count": len(artifacts),
        "timeline_count": len(timeline),
        "hunt_count": len(hunt_results),
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_case(mgr: CaseMgrDep, _: AuthDep, body: CaseCreate) -> dict:
    case = mgr.create_case(name=body.name, analyst=body.analyst, notes=body.notes)
    events.emit("case.created", {"case_id": case.id, "name": case.name})
    return case.to_dict()


@router.patch("/{case_id}")
def update_case(mgr: CaseMgrDep, _: AuthDep, case_id: str, body: CaseUpdate) -> dict:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")
    ok = mgr.update_case(case_id, **updates)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Update rejected (no matching updatable columns)")
    updated = mgr.get_case(case_id)
    assert updated is not None  # checked above
    events.emit("case.updated", {"case_id": case_id, "fields": list(updates.keys())})
    return updated.to_dict()


@router.post("/{case_id}/close")
def close_case(mgr: CaseMgrDep, _: AuthDep, case_id: str) -> dict:
    if not mgr.close_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    events.emit("case.closed", {"case_id": case_id})
    return {"case_id": case_id, "status": "closed"}


@router.delete("/{case_id}", status_code=status.HTTP_200_OK)
def delete_case(mgr: CaseMgrDep, _: AuthDep, case_id: str) -> dict:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    mgr.delete_case(case_id)
    events.emit("case.deleted", {"case_id": case_id})
    return {"case_id": case_id, "deleted": True}


@router.get("/{case_id}/evidence")
def list_evidence(mgr: CaseMgrDep, _: AuthDep, case_id: str) -> dict:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return {"evidence": mgr.list_evidence(case_id)}


@router.get("/{case_id}/artifacts")
def list_artifacts(mgr: CaseMgrDep, _: AuthDep, case_id: str, source: str | None = None) -> dict:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return {"artifacts": mgr.list_artifacts(case_id, source)}


@router.get("/{case_id}/timeline")
def get_timeline(mgr: CaseMgrDep, _: AuthDep, case_id: str) -> dict:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return {"timeline": mgr.get_timeline(case_id)}


@router.get("/{case_id}/hunt-results")
def get_hunt_results(mgr: CaseMgrDep, _: AuthDep, case_id: str) -> dict:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return {"hunt_results": mgr.get_hunt_results(case_id)}


@router.post("/{case_id}/verify")
def verify_case_evidence(mgr: CaseMgrDep, _: AuthDep, case_id: str) -> dict:
    """Re-verify chain of custody for all evidence in a case."""
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    em = EvidenceManager(mgr)
    results = []
    for ev in mgr.list_evidence(case_id):
        results.append({"evidence_id": ev["id"], **em.verify_evidence(case_id, ev["id"])})
    return {"verifications": results}
