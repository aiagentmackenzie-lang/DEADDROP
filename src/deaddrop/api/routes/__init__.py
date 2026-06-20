"""Routes package — aggregates all API routers."""

from __future__ import annotations

from deaddrop.api.routes.analysis import router as analysis_router
from deaddrop.api.routes.cases import router as cases_router
from deaddrop.api.routes.evidence import router as evidence_router
from deaddrop.api.routes.hunt import router as hunt_router
from deaddrop.api.routes.plugins import router as plugins_router
from deaddrop.api.routes.reports import router as reports_router

__all__ = [
    "analysis_router",
    "cases_router",
    "evidence_router",
    "hunt_router",
    "plugins_router",
    "reports_router",
]
