from uuid import uuid4

from fastapi.testclient import TestClient

from baselineguard_api.main import app


def test_liveness_is_public_and_minimal() -> None:
    response = TestClient(app).get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "x-request-id" in response.headers


def test_protected_api_fails_closed_without_a_principal() -> None:
    response = TestClient(app).get("/api/v1/me", headers={"X-Request-ID": "attacker-supplied"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "AUTHENTICATION_REQUIRED"
    assert response.json()["request_id"] != "attacker-supplied"

    cancel_response = TestClient(app).post(f"/api/v1/scans/{uuid4()}/cancel")
    assert cancel_response.status_code == 401
    assert cancel_response.json()["code"] == "AUTHENTICATION_REQUIRED"


def test_route_prefix_is_versioned_once() -> None:
    paths = set(app.openapi()["paths"])
    assert "/api/v1/assets" in paths
    assert "/api/v1/sites" in paths
    assert "/api/v1/scans" in paths
    assert "/api/v1/scans/{scan_id}/cancel" in paths
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/policy-drafts" in paths
    assert "/api/v1/policy-drafts/{policy_id}/publish" in paths
    assert "/api/v1/api/v1/assets" not in paths


def test_demo_login_is_rejected_in_production() -> None:
    import pytest
    from pydantic import ValidationError

    from baselineguard_api.config import Settings

    with pytest.raises(ValidationError, match="BG_DEMO_LOGIN"):
        Settings(
            _env_file=None,
            environment="production",
            session_secret="x" * 40,
            demo_login=True,
        )


def test_demo_login_route_is_hidden_when_disabled(monkeypatch) -> None:
    from baselineguard_api.config import Settings
    from baselineguard_api.routes.v1 import auth

    monkeypatch.setattr(auth, "get_settings", lambda: Settings(_env_file=None))
    client = TestClient(app)
    assert client.get("/api/v1/auth/options").json() == {"demo_login": False}
    response = client.post(
        "/api/v1/auth/demo-login",
        json={"organization": "northwind", "username": "ava", "password": "anything"},
    )
    assert response.status_code == 404
    code = client.post("/api/v1/auth/demo-code", json={"challenge": "0" * 60})
    assert code.status_code == 404
