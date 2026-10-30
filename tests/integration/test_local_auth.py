import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from baselineguard_persistence.models import (
    AuthChallenge,
    AuthSession,
    Organization,
    RoleBinding,
    User,
)
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.orm import Session

from baselineguard_api import security
from baselineguard_api.config import Settings
from baselineguard_api.crypto import seal
from baselineguard_api.identity import hash_password, recovery_hash, totp_code
from baselineguard_api.main import app
from baselineguard_api.routes.v1 import auth

pytestmark = pytest.mark.integration


@pytest.fixture
def identity_lab(monkeypatch, tmp_path):
    url = os.getenv("BG_MIGRATION_DATABASE_URL")
    if not url:
        pytest.skip("Set BG_MIGRATION_DATABASE_URL for local identity integration tests")
    key = tmp_path / "key"
    key.write_bytes(b"z" * 32)
    settings = Settings(_env_file=None, environment="test", master_key_file=str(key))
    engine = create_engine(url, hide_parameters=True)
    org_id, user_id = uuid4(), uuid4()
    secret = b"12345678901234567890"
    recovery = "A1" * 10
    with engine.connect() as conn:
        transaction = conn.begin()
        with Session(conn) as db, db.begin():
            db.add(Organization(id=org_id, slug=f"auth-{org_id}", name="Auth test"))
            db.flush()
            db.execute(text("SELECT set_config('app.org_id', :id, true)"), {"id": str(org_id)})
            db.add(
                User(
                    id=user_id,
                    org_id=org_id,
                    subject="operator",
                    auth_provider="local",
                    email="operator@example.test",
                    password_hash=hash_password("test long passphrase"),
                    totp_ciphertext=seal(
                        secret, binding=f"{org_id}/{user_id}/totp", master_key_file=str(key)
                    ),
                    last_totp_step=-1,
                    recovery_hashes=[recovery_hash(recovery)],
                )
            )
            db.flush()
            db.add(RoleBinding(id=uuid4(), org_id=org_id, user_id=user_id, role="viewer"))
        for module in (auth, security):
            monkeypatch.setattr(module, "get_engine", lambda _: conn)
            monkeypatch.setattr(module, "get_settings", lambda: settings)
            monkeypatch.setattr(
                module,
                "Session",
                lambda bind: Session(bind, join_transaction_mode="create_savepoint"),
            )
        with TestClient(app, base_url="https://testserver") as client:
            yield client, conn, org_id, user_id, secret, recovery
        transaction.rollback()
    engine.dispose()


def sign_in(client, org_id):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "organization": f"auth-{org_id}",
            "username": "operator",
            "password": "test long passphrase",
        },
    )
    assert response.status_code == 202, response.text
    assert client.get("/api/v1/me").status_code == 401
    return response.json()["challenge"]


def test_password_mfa_cookie_csrf_logout_and_replay(identity_lab):
    client, conn, org, user, secret, recovery = identity_lab
    challenge = sign_in(client, org)
    code = totp_code(secret, int(datetime.now(UTC).timestamp() // 30))
    response = client.post("/api/v1/auth/mfa/verify", json={"challenge": challenge, "code": code})
    assert response.status_code == 200, response.text
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    me = client.get("/api/v1/me")
    assert me.status_code == 200 and me.json()["user_id"] == str(user)
    assert client.post("/api/v1/auth/logout").status_code == 403
    assert (
        client.post(
            "/api/v1/auth/mfa/verify", json={"challenge": challenge, "code": code}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/logout", headers={"X-CSRF-Token": response.json()["csrf_token"]}
        ).status_code
        == 204
    )
    assert client.get("/api/v1/me").status_code == 401
    assert conn.execute(select(AuthSession.revoked_at)).scalar_one() is not None


def test_recovery_is_one_use_and_idle_session_expires(identity_lab):
    client, conn, org, user, secret, recovery = identity_lab
    challenge = sign_in(client, org)
    verified = client.post(
        "/api/v1/auth/mfa/verify", json={"challenge": challenge, "recovery_code": recovery}
    )
    assert verified.status_code == 200
    conn.execute(update(AuthSession).values(last_seen_at=datetime.now(UTC) - timedelta(minutes=31)))
    assert client.get("/api/v1/me").status_code == 401
    challenge = sign_in(client, org)
    assert (
        client.post(
            "/api/v1/auth/mfa/verify", json={"challenge": challenge, "recovery_code": recovery}
        ).status_code
        == 401
    )


def test_failed_mfa_attempts_commit_and_challenge_locks(identity_lab):
    client, conn, org, user, secret, recovery = identity_lab
    challenge = sign_in(client, org)
    for _ in range(6):
        assert (
            client.post(
                "/api/v1/auth/mfa/verify", json={"challenge": challenge, "recovery_code": "B2" * 10}
            ).status_code
            == 401
        )
    assert conn.execute(select(AuthChallenge.attempts)).scalar_one() == 5
    assert (
        client.post(
            "/api/v1/auth/mfa/verify", json={"challenge": challenge, "recovery_code": recovery}
        ).status_code
        == 401
    )


def test_authentication_rate_limit_persists_failed_attempts(identity_lab, monkeypatch):
    client, conn, org, user, secret, recovery = identity_lab
    monkeypatch.setattr(auth, "verify_password", lambda *_: False)
    statuses = [
        client.post(
            "/api/v1/auth/login",
            json={"organization": f"auth-{org}", "username": "operator", "password": "incorrect"},
        ).status_code
        for _ in range(21)
    ]
    assert statuses[:20] == [401] * 20
    assert statuses[-1] == 429


def test_demo_login_is_off_by_default(identity_lab):
    client, *_ = identity_lab
    assert client.get("/api/v1/auth/options").json() == {"demo_login": False}
    response = client.post(
        "/api/v1/auth/demo-login",
        json={"organization": "any", "username": "operator", "password": "x"},
    )
    assert response.status_code == 404


def test_demo_login_skips_mfa_but_checks_password_and_audits(identity_lab, monkeypatch):
    client, conn, org, user, *_ = identity_lab
    demo = Settings(
        _env_file=None,
        environment="test",
        demo_login=True,
        master_key_file=auth.get_settings().master_key_file,
    )
    monkeypatch.setattr(auth, "get_settings", lambda: demo)
    assert client.get("/api/v1/auth/options").json() == {"demo_login": True}
    body = {"organization": f"auth-{org}", "username": "operator"}
    wrong = client.post("/api/v1/auth/demo-login", json={**body, "password": "incorrect"})
    assert wrong.status_code == 401
    response = client.post(
        "/api/v1/auth/demo-login", json={**body, "password": "test long passphrase"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["csrf_token"]
    me = client.get("/api/v1/me")
    assert me.status_code == 200 and me.json()["user_id"] == str(user)
    factor = conn.execute(
        text(
            "SELECT redacted_details->>'factor' FROM audit_events "
            "WHERE org_id = :org AND action = 'auth.signed_in' ORDER BY sequence DESC LIMIT 1"
        ),
        {"org": str(org)},
    ).scalar_one()
    assert factor == "demo-password-only"


def test_demo_code_fills_mfa_only_in_demo_mode(identity_lab, monkeypatch):
    client, conn, org, user, *_ = identity_lab
    challenge = sign_in(client, org)
    assert client.post("/api/v1/auth/demo-code", json={"challenge": challenge}).status_code == 404
    demo = Settings(
        _env_file=None,
        environment="test",
        demo_login=True,
        master_key_file=auth.get_settings().master_key_file,
    )
    monkeypatch.setattr(auth, "get_settings", lambda: demo)
    bogus = client.post("/api/v1/auth/demo-code", json={"challenge": f"{org}." + "x" * 60})
    assert bogus.status_code == 401
    code = client.post("/api/v1/auth/demo-code", json={"challenge": challenge}).json()["code"]
    response = client.post("/api/v1/auth/mfa/verify", json={"challenge": challenge, "code": code})
    assert response.status_code == 200, response.text
    assert client.get("/api/v1/me").json()["user_id"] == str(user)
