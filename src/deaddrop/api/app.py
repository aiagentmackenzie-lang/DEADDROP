"""FastAPI application factory — the in-process DEADDROP API server.

Replaces the broken TS subprocess bridge (SB-2/3). Calls the Python engine
directly, with Pydantic validation (SB-4), bearer-token auth (SB-5), a
configurable CORS allowlist, a real WebSocket event bus (D-5), and serves the
built React dashboard as static files when present (SB-11 — works under any
install mode because there's no `parent⁴/server` path hop).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from deaddrop.api import events
from deaddrop.api.deps import AUTH_TOKEN_ENV, is_auth_enabled
from deaddrop.api.routes import (
    analysis_router,
    cases_router,
    evidence_router,
    hunt_router,
    plugins_router,
    reports_router,
)

log = logging.getLogger(__name__)


def _ws_idle_timeout() -> float:
    """Idle timeout before a WebSocket heartbeat. Read fresh so tests can tune it."""
    return float(os.environ.get("DEADDROP_WS_TIMEOUT", "30"))

# Where the built dashboard lives. Resolved against the package + repo layouts
# so it works under editable AND non-editable installs.
_DASHBOARD_CANDIDATES = [
    # Repo layout (editable / dev):  <repo>/dashboard/dist
    # app.py is at <repo>/src/deaddrop/api/app.py → parents[3] = <repo>
    Path(__file__).resolve().parents[3] / "dashboard" / "dist",
    # Wheel install (dashboard bundled alongside site-packages): best-effort
    Path(__file__).resolve().parents[2] / "dashboard" / "dist",
]


def _find_dashboard_dir() -> Path | None:
    for p in _DASHBOARD_CANDIDATES:
        if p.is_dir() and (p / "index.html").exists():
            return p
    return None


def _cors_origins() -> list[str]:
    """Configurable CORS allowlist. Default: localhost dashboard origins only."""
    raw = os.environ.get("DEADDROP_CORS_ORIGINS", "")
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    # Safe defaults — localhost dashboard dev + same-origin prod
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ]


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup: bind the event loop to the EventBus + warn on disabled auth.

    Binding the loop lets sync route handlers (which run in a worker thread)
    publish WebSocket events via call_soon_threadsafe.
    """
    import asyncio as _asyncio
    events.bus.bind_loop(_asyncio.get_running_loop())
    if not is_auth_enabled():
        log.warning(
            "DEADDROP API auth is DISABLED (%s unset). Set it in any "
            "non-loopback deployment.", AUTH_TOKEN_ENV,
        )
    dash = _find_dashboard_dir()
    if dash:
        app.mount("/", StaticFiles(directory=str(dash), html=True), name="dashboard")
        log.info("Serving dashboard from %s", dash)
    else:
        log.info(
            "Dashboard build not found (looked in %s). API-only mode. "
            "Build it with: cd dashboard && npm install && npm run build",
            _DASHBOARD_CANDIDATES,
        )
    yield
    # Shutdown — nothing to clean up; WS subscribers clean up on disconnect.


def create_app() -> FastAPI:
    """Build the FastAPI app with auth, CORS, routes, WebSocket, and static."""
    app = FastAPI(
        title="DEADDROP API",
        version="1.2.0",
        description="Digital Forensics Toolkit — in-process REST + WebSocket API",
        lifespan=_lifespan,
    )

    # CORS allowlist (SB-5: was `origin: true` — open to any origin)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Routers
    app.include_router(cases_router, prefix="/api/cases", tags=["cases"])
    app.include_router(evidence_router, prefix="/api/evidence", tags=["evidence"])
    app.include_router(analysis_router, prefix="/api/analyze", tags=["analyze"])
    app.include_router(hunt_router, prefix="/api/hunt", tags=["hunt"])
    app.include_router(reports_router, prefix="/api/reports", tags=["reports"])
    app.include_router(plugins_router, prefix="/api/plugins", tags=["plugins"])

    @app.get("/api/health")
    def health() -> dict:
        return {
            "status": "ok",
            "version": "1.2.0",
            "auth_enabled": is_auth_enabled(),
        }

    @app.websocket("/ws")
    async def ws_endpoint(socket: WebSocket) -> None:
        """Real WebSocket — streams case lifecycle events (D-5: was echo-only)."""
        await socket.accept()
        q = await events.bus.subscribe()
        idle_timeout = _ws_idle_timeout()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=idle_timeout)
                except TimeoutError:
                    # Heartbeat — keeps the connection alive and lets the client
                    # know the server is up even when idle.
                    await socket.send_text(json.dumps({"type": "heartbeat"}))
                    continue
                await socket.send_text(events.dumps(event))
        except WebSocketDisconnect:
            log.info("WebSocket client disconnected")
        finally:
            await events.bus.unsubscribe(q)



    return app


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Launch the API server via uvicorn (programmatic — works under any install)."""
    import uvicorn

    # Default to loopback unless the operator explicitly requests otherwise.
    # A forensics API should not bind 0.0.0.0 by default (SB-5).
    host = os.environ.get("DEADDROP_HOST", host)
    port = int(os.environ.get("DEADDROP_PORT", str(port)))
    log.info("Starting DEADDROP API on %s:%d (auth=%s)", host, port, is_auth_enabled())
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
