import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from baselineguard_persistence.database import get_engine
from baselineguard_persistence.models import AuthSession, Organization, RoleBinding, User
from fastapi import Depends, Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from baselineguard_api.config import get_settings
from baselineguard_api.errors import AppError
from baselineguard_api.identity import token_hash

SESSION_COOKIE = "__Host-bg_session"


def csrf_token(raw: str) -> str:
    return hmac.new(
        get_settings().session_secret.get_secret_value().encode(),
        b"csrf:" + raw.encode(),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    org_id: UUID
    roles: frozenset[str]
    site_ids: frozenset[UUID]
    mfa_verified_at: datetime | None = None
    session_id: UUID | None = None
    bindings: tuple[tuple[str, UUID | None], ...] = ()

    def sites_for(self, allowed_roles: set[str]) -> frozenset[UUID] | None:
        """None is an organization-wide grant; an empty set grants no sites."""
        if not self.bindings:
            if not self.roles.intersection(allowed_roles):
                return frozenset()
            return None if "platform_admin" in self.roles else self.site_ids
        matching = [site for role, site in self.bindings if role in allowed_roles]
        return (
            None if None in matching else frozenset(site for site in matching if site is not None)
        )


def require_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if isinstance(principal, Principal):
        return principal
    error = AppError(
        401,
        "AUTHENTICATION_REQUIRED",
        "Authentication required",
        "Sign in to continue.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    raw = request.cookies.get(SESSION_COOKIE, "")
    if not raw or len(raw) > 256:
        raise error
    try:
        org_id = UUID(raw.split(".", 1)[0])
    except ValueError:
        raise error from None
    now = datetime.now(UTC)
    with Session(get_engine(get_settings().database_url)) as db, db.begin():
        db.execute(text("SELECT set_config('app.org_id', :org_id, true)"), {"org_id": str(org_id)})
        session = db.execute(
            select(AuthSession)
            .where(
                AuthSession.token_hash == token_hash(raw),
                AuthSession.org_id == org_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
                AuthSession.last_seen_at > now - timedelta(minutes=30),
            )
            .with_for_update()
        ).scalar_one_or_none()
        if session is None:
            raise error
        user = db.get(User, session.user_id)
        org_status = db.execute(
            select(Organization.status).where(Organization.id == org_id)
        ).scalar_one_or_none()
        if user is None or user.disabled_at is not None or org_status != "active":
            raise error
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            submitted = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(submitted, csrf_token(raw)):
                raise AppError(
                    403, "CSRF_REJECTED", "Request rejected", "Refresh your session and try again."
                )
        rows = db.execute(
            select(RoleBinding.role, RoleBinding.site_id).where(
                RoleBinding.org_id == org_id,
                RoleBinding.user_id == user.id,
            )
        ).all()
        principal = Principal(
            user_id=user.id,
            org_id=org_id,
            roles=frozenset(row.role for row in rows),
            site_ids=frozenset(row.site_id for row in rows if row.site_id),
            mfa_verified_at=session.mfa_verified_at,
            session_id=session.id,
            bindings=tuple((row.role, row.site_id) for row in rows),
        )
        session.last_seen_at = now
    request.state.principal = principal
    return principal


def require_recent_mfa(principal: Principal) -> None:
    if principal.mfa_verified_at is None or principal.mfa_verified_at < datetime.now(
        UTC
    ) - timedelta(minutes=5):
        raise AppError(
            403,
            "RECENT_MFA_REQUIRED",
            "Verify your identity",
            "Sign in with MFA again before performing this action.",
        )


def require_roles(*allowed_roles: str):
    async def dependency(principal: Annotated[Principal, Depends(require_principal)]) -> Principal:
        if not principal.roles.intersection(allowed_roles):
            raise AppError(
                403, "FORBIDDEN", "Access denied", "You do not have permission for this action."
            )
        return principal

    return dependency
