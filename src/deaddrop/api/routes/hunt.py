"""Hunt routes — YARA + IOC, in-process."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from deaddrop.api import events
from deaddrop.api.deps import AuthDep, CaseMgrDep
from deaddrop.api.models import HuntIOCRequest, HuntYaraRequest, TriageRequest

router = APIRouter()


def _require_case(mgr, case_id: str) -> None:
    if not mgr.get_case(case_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")


@router.post("/yara")
def hunt_yara(mgr: CaseMgrDep, _: AuthDep, body: HuntYaraRequest) -> dict:
    from deaddrop.hunt.yara_scanner import YARAScanner
    _require_case(mgr, body.case_id)
    scanner = YARAScanner(mgr)
    results: dict = {"yara_hits": 0, "pack_hits": 0, "error": None}
    if body.yara_rules:
        r = scanner.scan(body.case_id, body.yara_rules)
        if "error" in r:
            results["error"] = r["error"]
        else:
            results["yara_hits"] = r.get("hits", 0)
    if body.pack:
        r = scanner.scan_pack(body.case_id, body.pack)
        if "error" in r:
            results["error"] = r["error"]
        else:
            results["pack_hits"] = r.get("hits", 0)
    events.emit("hunt.yara", {"case_id": body.case_id, "results": results})
    return results


@router.post("/ioc")
def hunt_ioc(mgr: CaseMgrDep, _: AuthDep, body: HuntIOCRequest) -> dict:
    from deaddrop.hunt.ioc_matcher import IOCMatcher
    _require_case(mgr, body.case_id)
    matcher = IOCMatcher(mgr)
    r = matcher.match(body.case_id, body.ioc_path)
    if r.get("error"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=r["error"])
    events.emit("hunt.ioc", {"case_id": body.case_id, "hits": r["hits"]})
    return r


@router.post("/ioc/patterns")
def hunt_ioc_patterns(mgr: CaseMgrDep, _: AuthDep, body: TriageRequest) -> dict:
    """Auto-detect IOCs in evidence using the built-in regex patterns."""
    from deaddrop.hunt.ioc_matcher import IOCMatcher
    _require_case(mgr, body.case_id)
    r = IOCMatcher(mgr).match_patterns(body.case_id)
    events.emit("hunt.ioc_patterns", {"case_id": body.case_id, "results": r})
    return r
