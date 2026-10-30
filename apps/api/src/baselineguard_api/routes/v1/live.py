"""Live-collection onboarding: pin a device's SSH host key and bind audit credentials.

Flow (trust on first use with explicit confirmation):
1. POST /assets/{id}/host-key  -> the API connects (scope-checked) and returns the
   server's host-key fingerprint. Nothing is stored.
2. The administrator compares that fingerprint with the device console.
3. POST /assets/{id}/connect   -> the API re-reads the key, refuses if it changed,
   pins it in known_hosts, records AssetTrust, seals the credential and binds it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

import paramiko
from baselineguard_adapters.base.transport import TargetScopeError, resolve_authorized_endpoint
from baselineguard_credentials.envelope import seal_credential
from baselineguard_persistence.models import Asset, AssetCredential, AssetTrust, Credential, Site
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, SecretStr, model_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from baselineguard_api.audit import append_audit_event
from baselineguard_api.config import get_settings
from baselineguard_api.dependencies import get_org_db
from baselineguard_api.errors import AppError
from baselineguard_api.routes.v1.inventory import LIVE_SSH_ADAPTERS
from baselineguard_api.security import Principal, require_principal

router = APIRouter(tags=["live-collection"])
PrincipalDep = Annotated[Principal, Depends(require_principal)]
DbDep = Annotated[Session, Depends(get_org_db)]
CONNECT_ROLES = {"platform_admin", "credential_admin"}
_known_hosts_lock = threading.Lock()


class HostKeyRead(BaseModel):
    key_type: str
    fingerprint: str


class ConnectRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr | None = Field(default=None, max_length=1024)
    private_key_pem: SecretStr | None = Field(default=None, max_length=16384)
    fingerprint: str = Field(min_length=10, max_length=128)

    @model_validator(mode="after")
    def one_secret(self):
        if (self.password is None) == (self.private_key_pem is None):
            raise ValueError("Provide exactly one of password or private_key_pem")
        return self


def fingerprint_of(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def known_hosts_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def _load_asset(db: Session, principal: Principal, asset_id: UUID) -> tuple[Asset, Site]:
    asset = db.execute(
        select(Asset).where(
            Asset.org_id == principal.org_id, Asset.id == asset_id, Asset.archived_at.is_(None)
        )
    ).scalar_one_or_none()
    site = db.get(Site, asset.site_id) if asset else None
    if asset is None or site is None:
        raise AppError(404, "NOT_FOUND", "Not found", "The requested resource is not available.")
    if asset.adapter_id not in LIVE_SSH_ADAPTERS:
        raise AppError(
            422, "NOT_A_LIVE_SSH_ASSET", "Not supported",
            "Only live SSH assets (linux-ssh, windows-ssh, cisco-iosxe, fortigate-ssh) use host-key pinning.",
        )
    return asset, site


def _probe(asset: Asset, site: Site) -> paramiko.PKey:
    settings = get_settings()
    scope = site.scope or {}
    try:
        endpoint = resolve_authorized_endpoint(
            asset.address,
            asset.port,
            allowed_cidrs=tuple(scope.get("allowed_cidrs", [])),
            allowed_dns_suffixes=tuple(scope.get("allowed_dns_suffixes", [])),
            allowed_ports=tuple(scope.get("allowed_ports", [])),
            allow_loopback=settings.lab_targets and settings.environment != "production",
        )
    except TargetScopeError as error:
        raise AppError(422, str(error), "Target out of scope", "The asset is outside its site's authorized scope.") from None
    transport = None
    try:
        sock = socket.create_connection((endpoint.connect_ip, endpoint.port), timeout=8)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=8)
        return transport.get_remote_server_key()
    except (OSError, paramiko.SSHException, EOFError):
        raise AppError(
            502, "TARGET_UNREACHABLE", "Device unreachable",
            f"Could not open an SSH session to {asset.address}:{asset.port}.",
        ) from None
    finally:
        if transport is not None:
            transport.close()


@router.post("/assets/{asset_id}/host-key", response_model=HostKeyRead)
def read_host_key(asset_id: UUID, principal: PrincipalDep, db: DbDep) -> HostKeyRead:
    if not principal.roles & CONNECT_ROLES:
        raise AppError(403, "FORBIDDEN", "Access denied", "You do not have permission for this action.")
    asset, site = _load_asset(db, principal, asset_id)
    key = _probe(asset, site)
    return HostKeyRead(key_type=key.get_name(), fingerprint=fingerprint_of(key))


@router.post("/assets/{asset_id}/connect")
def connect_asset(asset_id: UUID, body: ConnectRequest, principal: PrincipalDep, db: DbDep) -> dict[str, str]:
    if not principal.roles & CONNECT_ROLES:
        raise AppError(403, "FORBIDDEN", "Access denied", "You do not have permission for this action.")
    settings = get_settings()
    asset, site = _load_asset(db, principal, asset_id)
    key = _probe(asset, site)
    fingerprint = fingerprint_of(key)
    if fingerprint != body.fingerprint.strip():
        raise AppError(
            409, "HOST_KEY_CHANGED", "Host key changed",
            "The device presented a different host key than the one you confirmed. Nothing was saved.",
        )

    # 1. Pin the key where the collector enforces it (RejectPolicy for anything else).
    path = Path(settings.known_hosts_file)
    with _known_hosts_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        hosts = paramiko.HostKeys(str(path))
        name = known_hosts_name(asset.address, asset.port)
        if name in hosts:
            del hosts[name]
        hosts.add(name, key.get_name(), key)
        hosts.save(str(path))

    now = datetime.now(UTC)
    # 2. Record trust (revoking any earlier pin).
    for old in db.execute(
        select(AssetTrust).where(
            AssetTrust.org_id == principal.org_id,
            AssetTrust.asset_id == asset.id,
            AssetTrust.revoked_at.is_(None),
        )
    ).scalars():
        old.revoked_at = now
    db.flush()
    db.add(AssetTrust(
        id=uuid4(), org_id=principal.org_id, asset_id=asset.id, trust_type="ssh_host_key",
        fingerprint=fingerprint, verified_by=principal.user_id, verified_at=now,
    ))

    # 3. Seal and bind the credential.
    credential_id = uuid4()
    secret = {"username": body.username}
    if body.password is not None:
        secret["password"] = body.password.get_secret_value()
    else:
        secret["private_key_pem"] = body.private_key_pem.get_secret_value()  # type: ignore[union-attr]
    db.execute(
        delete(AssetCredential).where(
            AssetCredential.org_id == principal.org_id,
            AssetCredential.asset_id == asset.id,
            AssetCredential.purpose == "audit_collect",
        )
    )
    db.add(Credential(
        id=credential_id, org_id=principal.org_id,
        name=f"{asset.name}-audit-{credential_id.hex[:8]}",
        kind="ssh_password" if body.password is not None else "ssh_key",
        encrypted_secret=seal_credential(
            json.dumps(secret).encode(), org_id=str(principal.org_id),
            credential_id=str(credential_id), master_key_file=settings.master_key_file,
        ),
        key_version="local-v1", credential_metadata={"username": body.username},
        created_by=principal.user_id,
    ))
    db.flush()
    db.add(AssetCredential(
        org_id=principal.org_id, asset_id=asset.id, credential_id=credential_id, purpose="audit_collect",
    ))
    append_audit_event(
        db, principal, action="asset.live_connected", object_type="asset", object_id=asset.id,
        details={"fingerprint": fingerprint, "username": body.username},
    )
    return {"status": "connected", "fingerprint": fingerprint}
