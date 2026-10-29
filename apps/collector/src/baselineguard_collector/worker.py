"""Collection worker loop.

Claims COLLECT jobs, dispatches the fixed read-only adapters, persists the
immutable normalized snapshot, then enqueues the evaluation job. Live SSH
collection resolves and authorizes the target against the site scope and
strict known-hosts file; `...-fixture` adapters read declared raw-output
fixture files and are stamped `source='fixture'` end to end.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from baselineguard_adapters.base.transport import (
    ResolvedEndpoint,
    SSHCredential,
    resolve_authorized_endpoint,
)
from baselineguard_adapters.linux.ssh import LINUX_READERS, UbuntuSSHReader
from baselineguard_credentials.envelope import unseal_credential
from baselineguard_evidence.bundle import ArtifactStore
from baselineguard_persistence.database import get_engine
from baselineguard_persistence.models import (
    Asset,
    AssetCredential,
    AssetTrust,
    Credential,
    Job,
    ScanRun,
    ScanTarget,
    Site,
)
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from baselineguard_collector.snapshot_store import (
    CollectionOutcome,
    persist_snapshot,
    read_outputs_from_fixture,
)

LIVE_ADAPTERS = ("linux-ssh", "windows-local", "fortigate-ssh", "cisco-iosxe")
FIXTURE_ADAPTERS = (
    "linux-ssh-fixture",
    "cisco-iosxe-fixture",
    "windows-fixture",
    "fortigate-fixture",
)


class CollectorWorker:
    def __init__(
        self,
        *,
        database_url: str,
        evidence_root: str,
        master_key_file: str,
        known_hosts_file: str | None = None,
        fixture_root: str | None = None,
        poll_seconds: float = 2.0,
        one_shot: bool = False,
        reader_timeout_seconds: int = 10,
    ):
        self.engine = get_engine(database_url)
        self.poll_seconds = poll_seconds
        self.one_shot = one_shot
        self.evidence_root = evidence_root
        self.master_key_file = master_key_file
        self.known_hosts_file = known_hosts_file
        self.fixture_root = Path(fixture_root) if fixture_root else None
        self.reader_timeout_seconds = reader_timeout_seconds
        self.store = ArtifactStore(evidence_root, master_key_file)

    def run_forever(self) -> None:
        while True:
            if self.run_one():
                continue
            if self.one_shot:
                return
            time.sleep(self.poll_seconds)

    def run_one(self) -> bool:
        lease_token = uuid4()
        session = Session(self.engine)
        try:
            with session.begin():
                db = session
                job = db.execute(
                    select(Job)
                    .where(
                        Job.kind == "COLLECT",
                        Job.state == "QUEUED",
                        Job.cancel_requested_at.is_(None),
                    )
                    .order_by(Job.available_at, Job.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                ).scalar_one_or_none()
                if job is None:
                    return False
                job.state = "RUNNING"
                job.lease_owner = uuid4()
                job.lease_token = lease_token
                job.lease_expires_at = datetime.now(UTC) + timedelta(minutes=5)
                job.attempt = (job.attempt or 0) + 1
                try:
                    self._process(db, job, lease_token)
                except CollectionFailure as failure:
                    # Retryable transport bounds; non-retryable codes dead-letter.
                    job.state = "RETRY_WAIT" if failure.retryable else "DEAD_LETTER"
                    job.lease_owner = None
                    job.lease_token = None
                    job.lease_expires_at = None
                    if failure.retryable:
                        job.available_at = datetime.now(UTC) + timedelta(
                            seconds=30 * (2 ** job.attempt)
                        )
                except Exception as error:  # noqa: BLE001 - job pipeline boundary
                    job.state = "DEAD_LETTER"
                    job.error_code = "COLLECTOR_UNEXPECTED"
                    job.lease_owner = None
                    job.lease_token = None
                    job.lease_expires_at = None
                    del error
            return True
        finally:
            session.close()

    # --- processing -----------------------------------------------------------

    def _process(self, db: Session, job: Job, lease_token: UUID) -> None:
        target = db.get(ScanTarget, job.target_id)
        asset = db.get(Asset, target.asset_id) if target else None
        if target is None or asset is None:
            job.state = "DEAD_LETTER"
            job.error_code = "TARGET_UNRESOLVABLE"
            return
        target.state = "COLLECTING"
        target.started_at = target.started_at or datetime.now(UTC)
        try:
            outcome = self._collect(db, job, asset)
        except CollectionFailure:
            raise
        if (
            outcome.source == "live"
            and outcome.error_code is None
            and not self._trust_verified(db, asset)
        ):
            outcome.error_code = "TRUST_NOT_VERIFIED"

        snapshot_ref, envelope = persist_snapshot(
            db,
            self.store,
            outcome,
            org_id=job.org_id,
            asset_id=target.asset_id,
            target_id=target.id,
            collector_id=uuid4(),
        )
        claim_is_current = (
            update(Job)
            .where(
                Job.id == job.id,
                Job.org_id == job.org_id,
                Job.lease_token == lease_token,
                Job.cancel_requested_at.is_(None),
            )
            .values(
                state="COMPLETED",
                lease_owner=None,
                lease_token=None,
                lease_expires_at=None,
            )
        )
        fenced = db.execute(claim_is_current).rowcount  # type: ignore[union-attr]
        if fenced == 0:  # lease lost or cancelled mid-collection
            return
        target.state = "EVALUATING"
        target.frozen_identity = dict(envelope.get("identity") or {})
        policy_id = str(job.payload_ref["policy_id"])
        db.add(
            Job(
                id=uuid4(),
                org_id=job.org_id,
                target_id=target.id,
                kind="EVALUATE",
                state="QUEUED",
                attempt=0,
                max_attempts=3,
                payload_ref={
                    "asset_id": str(target.asset_id),
                    "policy_id": policy_id,
                    "snapshot_id": snapshot_ref["snapshot_id"],
                    "source": outcome.source,
                    "error_code": outcome.error_code,
                },
            )
        )
        run = db.get(ScanRun, target.run_id)
        if run is not None and run.status in {"QUEUED", "PREFLIGHT"}:
            run.status = "EVALUATING"
            run.started_at = run.started_at or datetime.now(UTC)

    def _collect(self, db: Session, job: Job, asset: Asset) -> CollectionOutcome:
        adapter_id = asset.adapter_id
        now = datetime.now(UTC)
        identity: dict[str, Any] = {
            **(asset.identity or {}),
            "adapter_id": adapter_id,
            "stable_device_id": str(asset.id),
        }
        if adapter_id in FIXTURE_ADAPTERS:
            fixture_name = str(job.payload_ref.get("fixture_name") or "")
            fixture = json.loads(self._fixture_path(fixture_name).read_text(encoding="utf-8"))
            outputs = read_outputs_from_fixture(fixture, adapter_id)
            return CollectionOutcome(
                adapter_id=adapter_id,
                reader_outputs=outputs,
                error_code=None,
                source="fixture",
                observed_start=now - timedelta(seconds=5),
                observed_end=now,
                identity=identity,
            )
        if adapter_id == "linux-ssh":
            return self._collect_linux_live(db, job, asset, identity, now)
        if adapter_id == "windows-local":
            return self._collect_windows_live(db, job, asset, identity, now)
        if adapter_id == "fortigate-ssh":
            return self._collect_fortigate_live(db, job, asset, identity, now)
        if adapter_id == "cisco-iosxe":
            return self._collect_cisco_live(db, job, asset, identity, now)
        raise CollectionFailure("UNSUPPORTED_ADAPTER", retryable=False)

    def _collect_cisco_live(
        self, db: Session, job: Job, asset: Asset, identity: dict[str, Any], now: datetime
    ) -> CollectionOutcome:
        from baselineguard_adapters.cisco_iosxe.reader import IOSXE_READERS, CiscoIOSXEReader

        site = db.get(Site, asset.site_id)
        scope = (site.scope if site is not None else {}) or {}
        try:
            endpoint = resolve_authorized_endpoint(
                asset.address,
                asset.port,
                allowed_cidrs=tuple(scope.get("allowed_cidrs", [])),
                allowed_dns_suffixes=tuple(scope.get("allowed_dns_suffixes", [])),
                allowed_ports=tuple(scope.get("allowed_ports", [])),
            )
        except ValueError as error:
            raise CollectionFailure(str(error), retryable=False) from None
        credential = self._ssh_credential(db, asset)
        role = asset.declared_role if asset.declared_role in ("router", "switch") else "switch"
        reader = CiscoIOSXEReader(
            known_hosts=Path(self.known_hosts_file or "/etc/baselineguard/known_hosts"),
            role=role,
            timeout_seconds=self.reader_timeout_seconds,
        )
        try:
            outputs = reader.collect(endpoint, credential, tuple(sorted(IOSXE_READERS)))
        except Exception as error:
            raise CollectionFailure(str(error), retryable=False) from None
        return CollectionOutcome(
            adapter_id=asset.adapter_id,
            reader_outputs=outputs,
            error_code=None,
            source="live",
            observed_start=now - timedelta(seconds=5),
            observed_end=now,
            identity=identity,
        )

    def _collect_windows_live(
        self, db: Session, job: Job, asset: Asset, identity: dict[str, Any], now: datetime
    ) -> CollectionOutcome:
        from baselineguard_adapters.windows.reader import WINDOWS_READERS, WindowsReader

        reader = WindowsReader(timeout_seconds=self.reader_timeout_seconds)
        try:
            outputs = reader.collect(None, None, tuple(sorted(WINDOWS_READERS)))
        except Exception as error:
            raise CollectionFailure(str(error), retryable=False) from None
        return CollectionOutcome(
            adapter_id=asset.adapter_id,
            reader_outputs=outputs,
            error_code=None,
            source="live",
            observed_start=now - timedelta(seconds=5),
            observed_end=now,
            identity=identity,
        )

    def _collect_fortigate_live(
        self, db: Session, job: Job, asset: Asset, identity: dict[str, Any], now: datetime
    ) -> CollectionOutcome:
        from baselineguard_adapters.fortigate.reader import FORTIGATE_READERS, FortiGateReader

        site = db.get(Site, asset.site_id)
        scope = (site.scope if site is not None else {}) or {}
        try:
            endpoint = resolve_authorized_endpoint(
                asset.address,
                asset.port,
                allowed_cidrs=tuple(scope.get("allowed_cidrs", [])),
                allowed_dns_suffixes=tuple(scope.get("allowed_dns_suffixes", [])),
                allowed_ports=tuple(scope.get("allowed_ports", [])),
            )
        except ValueError as error:
            raise CollectionFailure(str(error), retryable=False) from None
        credential = self._ssh_credential(db, asset)
        reader = FortiGateReader(
            known_hosts=Path(self.known_hosts_file or "/etc/baselineguard/known_hosts"),
            timeout_seconds=self.reader_timeout_seconds,
        )
        try:
            outputs = reader.collect(endpoint, credential, tuple(sorted(FORTIGATE_READERS)))
        except Exception as error:
            raise CollectionFailure(str(error), retryable=False) from None
        return CollectionOutcome(
            adapter_id=asset.adapter_id,
            reader_outputs=outputs,
            error_code=None,
            source="live",
            observed_start=now - timedelta(seconds=5),
            observed_end=now,
            identity=identity,
        )

    def _collect_linux_live(
        self, db: Session, job: Job, asset: Asset, identity: dict[str, Any], now: datetime
    ) -> CollectionOutcome:
        from baselineguard_adapters.linux.ssh import CollectionError

        site = db.get(Site, asset.site_id)
        scope = (site.scope if site is not None else {}) or {}
        try:
            endpoint = resolve_authorized_endpoint(
                asset.address,
                asset.port,
                allowed_cidrs=tuple(scope.get("allowed_cidrs", [])),
                allowed_dns_suffixes=tuple(scope.get("allowed_dns_suffixes", [])),
                allowed_ports=tuple(scope.get("allowed_ports", [])),
            )
        except ValueError as error:
            raise CollectionFailure(str(error), retryable=False) from None
        credential = self._ssh_credential(db, asset)
        reader = UbuntuSSHReader(
            known_hosts=Path(self.known_hosts_file or "/etc/baselineguard/known_hosts"),
            timeout_seconds=self.reader_timeout_seconds,
        )
        try:
            outputs = reader.collect(endpoint, credential, tuple(sorted(LINUX_READERS)))
        except CollectionError as error:
            if error.code in {"SSH_AUTHENTICATION_FAILED", "SSH_HOST_KEY_MISMATCH"}:
                raise CollectionFailure(error.code, retryable=False) from None
            raise CollectionFailure(error.code, retryable=True) from None
        return CollectionOutcome(
            adapter_id=asset.adapter_id,
            reader_outputs=outputs,
            error_code=None,
            source="live",
            observed_start=now - timedelta(seconds=5),
            observed_end=now,
            identity=identity,
        )

    def _ssh_credential(self, db: Session, asset: Asset) -> SSHCredential:
        binding = db.execute(
            select(AssetCredential, Credential)
            .join(
                Credential,
                (Credential.org_id == AssetCredential.org_id)
                & (Credential.id == AssetCredential.credential_id),
            )
            .where(
                AssetCredential.org_id == asset.org_id,
                AssetCredential.asset_id == asset.id,
                AssetCredential.purpose == "audit_collect",
            )
            .limit(1)
        ).one_or_none()
        if binding is None:
            raise CollectionFailure("CREDENTIAL_NOT_BOUND", retryable=False)
        _link, credential_row = binding
        if credential_row.encrypted_secret is None:
            raise CollectionFailure("CREDENTIAL_MATERIEL_UNAVAILABLE", retryable=False)
        try:
            payload = json.loads(
                unseal_credential(
                    credential_row.encrypted_secret,
                    org_id=str(asset.org_id),
                    credential_id=str(credential_row.id),
                    master_key_file=self.master_key_file,
                )
            )
        except ValueError as error:
            raise CollectionFailure("CREDENTIAL_DECRYPT_FAILED", retryable=False) from error
        return SSHCredential(
            username=payload["username"],
            private_key=load_private_key(payload) if payload.get("private_key_pem") else None,
            password=payload.get("password"),
        )

    def _trust_verified(self, db: Session, asset: Asset) -> bool:
        row = db.execute(
            select(AssetTrust.id).where(
                AssetTrust.org_id == asset.org_id,
                AssetTrust.asset_id == asset.id,
                AssetTrust.revoked_at.is_(None),
            )
        ).first()
        return row is not None

    def _fixture_path(self, name: str) -> Path:
        if not name or self.fixture_root is None:
            raise CollectionFailure("FIXTURE_ROOT_NOT_CONFIGURED", retryable=False)
        candidate = Path(name)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise CollectionFailure("UNSAFE_FIXTURE_PATH", retryable=False)
        path = self.fixture_root / candidate
        if not path.is_file():
            raise CollectionFailure("FIXTURE_NOT_FOUND", retryable=False)
        return path

    def pinned_endpoint_from_payload(self, payload: dict[str, Any]) -> ResolvedEndpoint:
        return ResolvedEndpoint(
            original_host=str(payload["original_host"]),
            connect_ip=str(payload["connect_ip"]),
            port=int(payload["port"]),
        )


class CollectionFailure(Exception):
    def __init__(self, code: str, *, retryable: bool):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def load_private_key(payload: dict[str, str]) -> Any:
    import io

    import paramiko

    material = payload["private_key_pem"]
    passphrase = payload.get("private_key_passphrase")
    if not isinstance(passphrase, str):
        passphrase = None
    last_error: Exception | None = None
    for key_type in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_type.from_private_key(
                io.StringIO(material), password=passphrase
            )
        except (paramiko.SSHException, paramiko.PasswordRequiredException, ValueError) as error:
            last_error = error
    raise CollectionFailure("CREDENTIAL_KEY_INVALID", retryable=False) from last_error
