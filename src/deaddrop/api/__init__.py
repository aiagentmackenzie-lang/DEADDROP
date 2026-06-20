"""DEADDROP API — in-process FastAPI server (replaces the broken TS bridge).

The previous architecture shelled out to the `deaddrop` CLI from a Node server
and `JSON.parse`d Rich-formatted console output — which returned `{raw: "<ansi>"}`
for every call. This package is the fix: a real in-process FastAPI app that
calls the Python engine directly, with Pydantic validation, bearer-token auth,
and a real WebSocket event bus.

Public surface:
- `create_app()` -> FastAPI application (used by `deaddrop dashboard` and tests)
- `run_server(host, port)` -> launches uvicorn programmatically
"""

from __future__ import annotations

from deaddrop.api.app import create_app, run_server

__all__ = ["create_app", "run_server"]
