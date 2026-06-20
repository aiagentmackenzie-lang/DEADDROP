"""Plugin routes — list + run, in-process."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from deaddrop.api.deps import AuthDep
from deaddrop.api.models import PluginRunRequest
from deaddrop.core.case import CaseManager
from deaddrop.core.config import Config
from deaddrop.plugins.manager import PluginManager

router = APIRouter()


def _pm() -> PluginManager:
    return PluginManager(Config.load())


@router.get("/")
def list_plugins(_: AuthDep) -> dict:
    return {"plugins": _pm().list_plugins()}


@router.post("/run")
def run_plugin(_: AuthDep, body: PluginRunRequest) -> dict:
    pm = _pm()
    # Open a CaseManager so the plugin can access the case
    cfg = Config.load()
    cfg.ensure_dirs()
    with CaseManager(cfg.db_path) as mgr:
        if not mgr.get_case(body.case_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case {body.case_id} not found",
            )
        result = pm.run_plugin(body.name, body.case_id, case_manager=mgr)
    if not result.get("success", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "plugin failed"),
        )
    return result
