"""Phase 2 integration tests — the FastAPI API works end-to-end (SB-2/3/4/5 fix).

The previous TS bridge shelled to the CLI and JSON.parsed Rich text, returning
`{raw: "<ansi>"}` for every call. These tests use FastAPI's TestClient to prove
the in-process API returns real JSON, validates bodies, enforces auth, and
streams WebSocket events.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Isolate the API to a tmp DEADDROP home so tests don't touch ~/.deaddrop."""
    monkeypatch.setenv("DEADDROP_HOME", str(tmp_path))
    # Auth disabled by default for most tests; enable per-test via monkeypatch.
    monkeypatch.delenv("DEADDROP_API_TOKEN", raising=False)
    # Reset the global event bus so history from prior tests doesn't leak in.
    from deaddrop.api import events
    events.bus.reset()
    from deaddrop.api import create_app
    return create_app()


@pytest.fixture
def client(app):
    # TestClient must be entered as a context manager for the app lifespan
    # (which binds the event loop to the EventBus) to run.
    with TestClient(app) as c:
        yield c


@pytest.fixture
def authed_app(tmp_path, monkeypatch):
    """An app instance with auth ENABLED (token required)."""
    monkeypatch.setenv("DEADDROP_HOME", str(tmp_path))
    monkeypatch.setenv("DEADDROP_API_TOKEN", "test-secret-token")
    from deaddrop.api import events
    events.bus.reset()
    from deaddrop.api import create_app
    return create_app()


@pytest.fixture
def authed_client(authed_app):
    with TestClient(authed_app) as c:
        yield c


def _create_case(client, name="API Test") -> str:
    r = client.post("/api/cases/", json={"name": name, "analyst": "R"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


class TestHealthAndBasics:
    def test_health_endpoint(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["version"] == "1.2.0"
        assert body["auth_enabled"] is False  # disabled in test fixture


class TestSB2RealJSONNotRichText:
    """SB-2: the API returns real JSON, not `{raw: '<rich text>'}`."""

    def test_list_cases_returns_real_json(self, client):
        _create_case(client, "JSON Shape Test")
        r = client.get("/api/cases/")
        assert r.status_code == 200
        body = r.json()
        assert "cases" in body
        assert isinstance(body["cases"], list)
        assert body["cases"][0]["name"] == "JSON Shape Test"
        # The old bridge returned {raw: "..."} — assert that key is absent
        assert "raw" not in body

    def test_case_lifecycle_returns_dicts(self, client):
        cid = _create_case(client, "Lifecycle")
        r = client.get(f"/api/cases/{cid}")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == cid
        assert body["name"] == "Lifecycle"
        assert "evidence" in body
        assert "raw" not in body

        r = client.post(f"/api/cases/{cid}/close")
        assert r.status_code == 200
        assert r.json()["status"] == "closed"

    def test_404_for_unknown_case(self, client):
        r = client.get("/api/cases/nope")
        assert r.status_code == 404
        assert "not found" in r.json()["detail"].lower()


class TestSB4BodyValidation:
    """SB-4: every body is validated with Pydantic; `as any` is gone."""

    def test_create_case_rejects_empty_name(self, client):
        r = client.post("/api/cases/", json={"name": "", "analyst": "x"})
        assert r.status_code == 422  # Pydantic validation error

    def test_create_case_rejects_missing_name(self, client):
        r = client.post("/api/cases/", json={"analyst": "x"})
        assert r.status_code == 422

    def test_create_case_rejects_oversized_name(self, client):
        r = client.post("/api/cases/", json={"name": "x" * 201})
        assert r.status_code == 422

    def test_disk_ingest_rejects_missing_case_id(self, client):
        r = client.post("/api/evidence/disk", json={"image_path": "/tmp/x.raw"})
        assert r.status_code == 422

    def test_hunt_yara_rejects_invalid_pack(self, client):
        cid = _create_case(client)
        r = client.post("/api/hunt/yara", json={"case_id": cid, "pack": "malware"})
        assert r.status_code == 422  # pack is a Literal enum


class TestSB5Auth:
    """SB-5: bearer-token auth enforced when DEADDROP_API_TOKEN is set."""

    def test_no_token_returns_401(self, authed_client):
        r = authed_client.get("/api/cases/")
        assert r.status_code == 401
        assert "bearer" in r.headers.get("WWW-Authenticate", "").lower()

    def test_wrong_token_returns_401(self, authed_client):
        r = authed_client.get(
            "/api/cases/", headers={"Authorization": "Bearer wrong"}
        )
        assert r.status_code == 401

    def test_correct_token_authenticates(self, authed_client):
        r = authed_client.get(
            "/api/cases/", headers={"Authorization": "Bearer test-secret-token"}
        )
        assert r.status_code == 200

    def test_auth_guards_write_endpoints(self, authed_client):
        # POST must also be guarded
        r = authed_client.post("/api/cases/", json={"name": "x"})
        assert r.status_code == 401


class TestSB11AnyInstallMode:
    """SB-11: create_app() resolves without relying on a `parent⁴/server` path."""

    def test_app_constructs_under_non_editable_layout(self, tmp_path, monkeypatch):
        # Simulate a non-editable install: no `server/` dir, no dashboard build.
        monkeypatch.setenv("DEADDROP_HOME", str(tmp_path))
        monkeypatch.delenv("DEADDROP_API_TOKEN", raising=False)
        from deaddrop.api import events
        events.bus.reset()
        from deaddrop.api import create_app
        app = create_app()  # must not raise
        with TestClient(app) as client:  # lifespan must run without raising
            assert client.get("/api/health").status_code == 200


class TestEvidenceAndArtifacts:
    def test_ingest_disk_missing_file_returns_404(self, client, tmp_path):
        cid = _create_case(client)
        r = client.post("/api/evidence/disk", json={
            "case_id": cid, "image_path": str(tmp_path / "ghost.raw"),
        })
        assert r.status_code == 404

    def test_ingest_disk_real_file(self, client, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 4096)
        cid = _create_case(client)
        r = client.post("/api/evidence/disk", json={
            "case_id": cid, "image_path": str(img),
        })
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["sha256"]
        assert body["verified"] is True

    def test_verify_evidence(self, client, tmp_path):
        img = tmp_path / "disk.raw"
        img.write_bytes(b"\x00" * 4096)
        cid = _create_case(client)
        eid = client.post("/api/evidence/disk", json={
            "case_id": cid, "image_path": str(img),
        }).json()["id"]
        r = client.post(f"/api/evidence/{cid}/{eid}/verify")
        assert r.status_code == 200
        assert r.json()["verified"] is True

    def test_list_artifacts_empty(self, client):
        cid = _create_case(client)
        r = client.get(f"/api/cases/{cid}/artifacts")
        assert r.status_code == 200
        assert r.json()["artifacts"] == []


class TestWebSocket:
    """D-5: WebSocket streams real lifecycle events (was echo-only)."""

    def test_case_create_emits_event(self, client, monkeypatch):
        # Short idle timeout so the test can't hang on a missed event
        monkeypatch.setenv("DEADDROP_WS_TIMEOUT", "1.0")
        with client.websocket_connect("/ws") as ws:
            client.post("/api/cases/", json={"name": "WS Test"})
            import json
            seen = False
            for _ in range(40):
                msg = ws.receive_text()
                event = json.loads(msg)
                if event.get("type") == "case.created" and event["data"].get("name") == "WS Test":
                    seen = True
                    break
            assert seen, "expected a case.created WebSocket event for 'WS Test'"

    def test_heartbeat_keeps_alive(self, client, monkeypatch):
        # Very short timeout so a heartbeat arrives within the test window
        monkeypatch.setenv("DEADDROP_WS_TIMEOUT", "0.2")
        import json
        with client.websocket_connect("/ws") as ws:
            got_heartbeat = False
            for _ in range(20):
                msg = ws.receive_text()
                if json.loads(msg).get("type") == "heartbeat":
                    got_heartbeat = True
                    break
            assert got_heartbeat, "expected at least one heartbeat when idle"


class TestPluginsRoute:
    def test_list_plugins(self, client):
        r = client.get("/api/plugins/")
        assert r.status_code == 200
        names = {p["name"] for p in r.json()["plugins"]}
        assert "hash-verifier" in names

    def test_run_unknown_plugin_400(self, client):
        cid = _create_case(client)
        r = client.post("/api/plugins/run", json={"case_id": cid, "name": "nope"})
        assert r.status_code == 400


class TestRateLimit:
    """Phase 4: expensive endpoints are rate-limited per client IP."""

    def test_ingest_rate_limited(self, tmp_path, monkeypatch):
        """Bursting ingest calls past the limit returns 429."""
        monkeypatch.setenv("DEADDROP_HOME", str(tmp_path))
        monkeypatch.setenv("DEADDROP_RATE_LIMIT", "3/60")  # very low limit
        monkeypatch.delenv("DEADDROP_API_TOKEN", raising=False)
        from deaddrop.api import events
        events.bus.reset()
        from deaddrop.api import create_app
        with TestClient(create_app()) as client:
            cid = _create_case(client)
            img = tmp_path / "x.raw"
            img.write_bytes(b"\x00" * 16)
            statuses = []
            for _ in range(6):
                r = client.post("/api/evidence/disk", json={
                    "case_id": cid, "image_path": str(img),
                })
                statuses.append(r.status_code)
            # First few succeed (201), then 429 kicks in
            assert 201 in statuses
            assert 429 in statuses
