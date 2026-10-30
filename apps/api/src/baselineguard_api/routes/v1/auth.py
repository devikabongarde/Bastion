import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from baselineguard_contracts.common import Contract
from baselineguard_persistence.database import get_engine
from baselineguard_persistence.models import (
    AuthChallenge,
    AuthSession,
    AuthThrottle,
    Organization,
    User,
)
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field, SecretStr, model_validator
from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.config import get_settings
from baselineguard_api.crypto import unseal
from baselineguard_api.errors import AppError
from baselineguard_api.identity import (
    recovery_hash,
    token_hash,
    totp_code,
    verify_password,
    verify_totp,
)
from baselineguard_api.security import SESSION_COOKIE, Principal, csrf_token, require_principal

router = APIRouter(prefix="/auth", tags=["identity"])


class LoginRequest(Contract):
    organization: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    username: str = Field(min_length=1, max_length=255)
    password: SecretStr = Field(min_length=1, max_length=1024)


class MFAVerifyRequest(Contract):
    challenge: str = Field(min_length=60, max_length=256)
    code: str | None = Field(default=None, pattern=r"^[0-9]{6}$")
    recovery_code: SecretStr | None = Field(default=None, min_length=20, max_length=20)

    @model_validator(mode="after")
    def one_factor(self):
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("Provide one authentication code or recovery code")
        return self


def _scope(db: Session, org_id: UUID) -> None:
    db.execute(text("SELECT set_config('app.org_id', :id, true)"), {"id": str(org_id)})


def _rate_limit(request: Request, account: str) -> None:
    settings = get_settings()
    now = datetime.now(UTC)
    source = request.client.host if request.client else "unknown"
    limited = False
    with Session(get_engine(settings.database_url)) as db, db.begin():
        db.execute(delete(AuthThrottle).where(AuthThrottle.window_start < now - timedelta(days=1)))
        for identity, limit in (("source:" + source, 100), ("account:" + account, 20)):
            key = hmac.new(
                settings.session_secret.get_secret_value().encode(),
                identity.encode(),
                hashlib.sha256,
            ).hexdigest()
            db.execute(
                insert(AuthThrottle)
                .values(key_hash=key, window_start=now, attempts=0)
                .on_conflict_do_nothing()
            )
            row = db.execute(
                select(AuthThrottle).where(AuthThrottle.key_hash == key).with_for_update()
            ).scalar_one()
            if row.window_start <= now - timedelta(minutes=15):
                row.window_start, row.attempts = now, 0
            row.attempts += 1
            limited = limited or row.attempts > limit
    if limited:
        raise AppError(
            429,
            "AUTH_RATE_LIMITED",
            "Try again later",
            "Too many authentication attempts. Try again in 15 minutes.",
            headers={"Retry-After": "900"},
        )


@router.post("/login", status_code=202)
def login(body: LoginRequest, request: Request) -> dict[str, str]:
    username = body.username.casefold()
    _rate_limit(request, body.organization + ":" + username)
    now = datetime.now(UTC)
    challenge_token = None
    with Session(get_engine(get_settings().database_url)) as db, db.begin():
        org_id = db.execute(
            select(Organization.id).where(
                Organization.slug == body.organization, Organization.status == "active"
            )
        ).scalar_one_or_none()
        user = None
        if org_id:
            _scope(db, org_id)
            user = db.execute(
                select(User).where(
                    User.org_id == org_id, User.auth_provider == "local", User.subject == username
                )
            ).scalar_one_or_none()
        valid = verify_password(
            user.password_hash if user else None, body.password.get_secret_value()
        )
        if valid and user and user.disabled_at is None and user.totp_ciphertext:
            challenge_token = f"{org_id}.{secrets.token_urlsafe(32)}"
            db.execute(delete(AuthChallenge).where(AuthChallenge.expires_at < now))
            db.add(
                AuthChallenge(
                    id=uuid4(),
                    org_id=org_id,
                    user_id=user.id,
                    token_hash=token_hash(challenge_token),
                    attempts=0,
                    expires_at=now + timedelta(minutes=5),
                )
            )
    if challenge_token is None:
        raise AppError(
            401,
            "INVALID_CREDENTIALS",
            "Sign-in failed",
            "The sign-in details are invalid or the account is unavailable.",
        )
    return {"challenge": challenge_token, "next_step": "mfa", "expires_in_seconds": "300"}


@router.post("/mfa/verify")
def verify_mfa(body: MFAVerifyRequest, request: Request, response: Response) -> dict[str, str]:
    _rate_limit(request, "mfa:" + body.challenge)
    try:
        org_id = UUID(body.challenge.split(".", 1)[0])
    except ValueError:
        raise AppError(
            401,
            "INVALID_MFA",
            "Verification failed",
            "The challenge or verification code is invalid.",
        ) from None
    now = datetime.now(UTC)
    raw_session = None
    with Session(get_engine(get_settings().database_url)) as db, db.begin():
        _scope(db, org_id)
        challenge = db.execute(
            select(AuthChallenge)
            .where(
                AuthChallenge.token_hash == token_hash(body.challenge),
                AuthChallenge.org_id == org_id,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if (
            challenge
            and challenge.consumed_at is None
            and challenge.expires_at > now
            and challenge.attempts < 5
        ):
            challenge.attempts += 1
            user = db.execute(
                select(User).where(User.id == challenge.user_id).with_for_update()
            ).scalar_one_or_none()
            valid = False
            if user and user.disabled_at is None and user.totp_ciphertext:
                if body.recovery_code:
                    submitted_hash = recovery_hash(body.recovery_code.get_secret_value())
                    valid = any(
                        hmac.compare_digest(submitted_hash, saved) for saved in user.recovery_hashes
                    )
                    if valid:
                        user.recovery_hashes = [
                            saved for saved in user.recovery_hashes if saved != submitted_hash
                        ]
                else:
                    try:
                        secret = unseal(
                            user.totp_ciphertext,
                            binding=f"{org_id}/{user.id}/totp",
                            master_key_file=get_settings().master_key_file,
                        )
                    except (OSError, ValueError, InvalidTag):
                        raise AppError(
                            503,
                            "KEY_UNAVAILABLE",
                            "Sign-in unavailable",
                            "The local key provider is unavailable.",
                        ) from None
                    step = verify_totp(
                        secret,
                        body.code or "",
                        timestamp=now.timestamp(),
                        last_step=user.last_totp_step,
                    )
                    valid = step is not None
                    if step is not None:
                        user.last_totp_step = step
            if valid and user:
                challenge.consumed_at = now
                raw_session = _open_session(
                    db, org_id, user, now, factor="recovery" if body.recovery_code else "totp"
                )
    if raw_session is None:
        raise AppError(
            401,
            "INVALID_MFA",
            "Verification failed",
            "The challenge or verification code is invalid.",
        )
    return _authenticated(response, raw_session)


def _open_session(db: Session, org_id: UUID, user: User, now: datetime, *, factor: str) -> str:
    raw_session = f"{org_id}.{secrets.token_urlsafe(32)}"
    db.add(
        AuthSession(
            id=uuid4(),
            org_id=org_id,
            user_id=user.id,
            token_hash=token_hash(raw_session),
            mfa_verified_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=12),
        )
    )
    append_audit_event(
        db,
        Principal(user.id, org_id, frozenset(), frozenset()),
        action="auth.signed_in",
        object_type="user",
        object_id=user.id,
        details={"factor": factor},
    )
    return raw_session


def _authenticated(response: Response, raw_session: str) -> dict[str, str]:
    response.set_cookie(
        SESSION_COOKIE,
        raw_session,
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=43200,
    )
    return {"status": "authenticated", "csrf_token": csrf_token(raw_session)}


def _demo_login_enabled() -> bool:
    settings = get_settings()
    return settings.demo_login and settings.environment != "production"


@router.get("/options")
def sign_in_options() -> dict[str, bool]:
    """Public: tells the sign-in page which methods this deployment offers."""
    return {"demo_login": _demo_login_enabled()}


class DemoCodeRequest(Contract):
    challenge: str = Field(min_length=60, max_length=256)


@router.post("/demo-code")
def demo_code(body: DemoCodeRequest, request: Request) -> dict[str, str]:
    """Demo only: return the current authenticator code for a pending, password-verified
    challenge so the MFA step can be shown quickly. Disabled unless BG_DEMO_LOGIN=true."""
    if not _demo_login_enabled():
        raise AppError(404, "NOT_FOUND", "Not found", "Demo sign-in is not enabled.")
    _rate_limit(request, "demo-code:" + body.challenge)
    invalid = AppError(401, "INVALID_MFA", "Verification failed", "The challenge is invalid.")
    try:
        org_id = UUID(body.challenge.split(".", 1)[0])
    except ValueError:
        raise invalid from None
    now = datetime.now(UTC)
    with Session(get_engine(get_settings().database_url)) as db, db.begin():
        _scope(db, org_id)
        challenge = db.execute(
            select(AuthChallenge).where(
                AuthChallenge.token_hash == token_hash(body.challenge),
                AuthChallenge.org_id == org_id,
            )
        ).scalar_one_or_none()
        if not challenge or challenge.consumed_at is not None or challenge.expires_at <= now:
            raise invalid
        user = db.get(User, challenge.user_id)
        if not user or user.disabled_at is not None or not user.totp_ciphertext:
            raise invalid
        try:
            secret = unseal(
                user.totp_ciphertext,
                binding=f"{org_id}/{user.id}/totp",
                master_key_file=get_settings().master_key_file,
            )
        except (OSError, ValueError, InvalidTag):
            raise AppError(
                503, "KEY_UNAVAILABLE", "Sign-in unavailable", "The local key provider is unavailable."
            ) from None
        # Codes are single-use: if this window's code was already spent, hand out the next one
        # (verification accepts one step ahead).
        step = max(int(now.timestamp() // 30), user.last_totp_step + 1)
        return {"code": totp_code(secret, step)}


@router.post("/demo-login")
def demo_login(body: LoginRequest, request: Request, response: Response) -> dict[str, str]:
    """Password-only sign-in for live demos. Disabled unless BG_DEMO_LOGIN=true (never in
    production). The password is still verified and the session is audited as MFA-skipped."""
    if not _demo_login_enabled():
        raise AppError(404, "NOT_FOUND", "Not found", "Demo sign-in is not enabled.")
    username = body.username.casefold()
    _rate_limit(request, body.organization + ":" + username)
    now = datetime.now(UTC)
    raw_session = None
    with Session(get_engine(get_settings().database_url)) as db, db.begin():
        org_id = db.execute(
            select(Organization.id).where(
                Organization.slug == body.organization, Organization.status == "active"
            )
        ).scalar_one_or_none()
        user = None
        if org_id:
            _scope(db, org_id)
            user = db.execute(
                select(User).where(
                    User.org_id == org_id, User.auth_provider == "local", User.subject == username
                )
            ).scalar_one_or_none()
        valid = verify_password(
            user.password_hash if user else None, body.password.get_secret_value()
        )
        if valid and user and org_id and user.disabled_at is None:
            raw_session = _open_session(db, org_id, user, now, factor="demo-password-only")
    if raw_session is None:
        raise AppError(
            401,
            "INVALID_CREDENTIALS",
            "Sign-in failed",
            "The sign-in details are invalid or the account is unavailable.",
        )
    return _authenticated(response, raw_session)


@router.post("/logout", status_code=204)
def logout(response: Response, principal: Principal = Depends(require_principal)) -> None:
    with Session(get_engine(get_settings().database_url)) as db, db.begin():
        _scope(db, principal.org_id)
        session = db.get(AuthSession, principal.session_id) if principal.session_id else None
        if session:
            session.revoked_at = datetime.now(UTC)
            append_audit_event(
                db,
                principal,
                action="auth.signed_out",
                object_type="session",
                object_id=session.id,
                details={},
            )
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
