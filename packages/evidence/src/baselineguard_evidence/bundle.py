"""Evidence package: encrypted artifact storage, redaction, signed manifests
and offline verification of report bundles.

Materials never touch the database: artifacts are stored on an encrypted,
content-addressed volume keyed by plaintext SHA-256 with AES-256-GCM
envelope encryption, while report/scan manifests are signed with Ed25519.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

MANIFEST_SCHEMA_VERSION = "1.0"
BUNDLE_MAX_BYTES = 209_715_200  # 200 MiB expanded limit
BUNDLE_MAX_ENTRIES = 10_000
_ENVELOPE_MAX = 104_857_600  # 100 MiB per artifact envelope
_KEY_VERSION = "master-v1"


class EvidenceError(ValueError):
    pass


def _binding(org_id: str, artifact_id: str) -> bytes:
    return f"org:{org_id}:artifact:{artifact_id}".encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


sha256_hash = sha256_hex  # backwards-compatible alias


class ArtifactStore:
    """Content-addressed encrypted storage bound to one organization."""

    def __init__(self, root: str | Path, master_key_file: str | Path):
        self.root = Path(root)
        self.master_key_file = Path(master_key_file)
        if len(self.master_key_file.read_bytes()) != 32:
            raise EvidenceError("master key must contain exactly 32 bytes")

    def write(
        self,
        org_id: str,
        artifact_id: str,
        plaintext: bytes,
        *,
        media_type: str,
        classification: str = "redacted",
    ) -> dict[str, Any]:
        if not plaintext or len(plaintext) > _ENVELOPE_MAX:
            raise EvidenceError("artifact is empty or beyond the size limit")
        digest = sha256_hex(plaintext)
        nonce, wrap_nonce = os.urandom(12), os.urandom(12)
        master = AESGCM(self.master_key_file.read_bytes())
        data_key = AESGCM.generate_key(bit_length=256)
        aad = _binding(org_id, artifact_id)
        envelope = json.dumps(
            {
                "version": "1",
                "key_version": _KEY_VERSION,
                "media_type": media_type,
                "classification": classification,
                "sha256": digest,
                "nonce": base64.b64encode(nonce).decode(),
                "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
                "wrapped_key": base64.b64encode(
                    master.encrypt(wrap_nonce, data_key, aad)
                ).decode(),
                "ciphertext": base64.b64encode(
            AESGCM(data_key).encrypt(nonce, plaintext, aad)
        ).decode(),
            },
            sort_keys=True,
        ).encode("utf-8")
        # The envelope is bound (AAD) to this artifact id, so the file must belong to exactly
        # one artifact row. A digest-only key let files outlive rolled-back rows and later be
        # handed to a different artifact id that can never decrypt them.
        storage_key = f"{org_id}/{digest}-{artifact_id}.bgenc"
        relative = Path(storage_key)
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            # Content-addressed: identical bytes are already stored safely.
            return self._metadata(storage_key, envelope)
        temporary = target.with_suffix(".tmp-0000")
        temporary.write_bytes(envelope)
        os.replace(temporary, target)
        return self._metadata(storage_key, envelope)

    def _metadata(self, storage_key: str, envelope: bytes) -> dict[str, Any]:
        fields = json.loads(envelope)
        return {
            "storage_key": storage_key,
            "sha256": fields["sha256"],
            "media_type": fields["media_type"],
            "classification": fields["classification"],
            "key_version": fields["key_version"],
            "size_bytes": len(envelope),
        }

    def read(
        self, org_id: str, artifact_id: str, storage_key: str, *, require_hash: str | None = None
    ) -> bytes:
        target = self.root / storage_key
        try:
            envelope = target.read_bytes()
        except OSError as error:
            raise EvidenceError("ARTIFACT_STORAGE_UNAVAILABLE") from error
        if len(envelope) > _ENVELOPE_MAX:
            raise EvidenceError("ENVELOPE_LIMIT_EXCEEDED")
        try:
            fields = json.loads(envelope)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise EvidenceError("UNSUPPORTED_ENVELOPE") from None
        if not set(fields) <= {
            "version", "key_version", "media_type", "classification",
            "sha256", "nonce", "wrap_nonce", "wrapped_key", "ciphertext",
        } or fields.get("key_version") != _KEY_VERSION:
            raise EvidenceError("UNSUPPORTED_ENVELOPE")
        aad = _binding(org_id, artifact_id)
        try:
            decoded = {
                key: base64.b64decode(fields[key], validate=True)
                for key in ("nonce", "wrap_nonce", "wrapped_key", "ciphertext")
            }
            master = AESGCM(self.master_key_file.read_bytes())
            data_key = master.decrypt(decoded["wrap_nonce"], decoded["wrapped_key"], aad)
            plaintext = AESGCM(data_key).decrypt(decoded["nonce"], decoded["ciphertext"], aad)
        except (ValueError, KeyError):
            raise EvidenceError("ARTIFACT_DECRYPT_FAILED") from None
        digest = sha256_hash(plaintext)
        if digest != fields["sha256"] or (require_hash is not None and digest != require_hash):
            raise EvidenceError("ARTIFACT_HASH_MISMATCH")
        return plaintext


# --- Redaction ---------------------------------------------------------------

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(password|passwd|secret|token|api[-_]?key|community)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bkrb5\w*\s=\s*"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{8,}"),
    re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
)
REDACTED_REPLACEMENT = "<redacted:" + "opaque>"


def redact_text(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED_REPLACEMENT, redacted)
    return redacted


def redact_tree(value: Any) -> Any:
    """Redact secrets recursively; safe for JSON-like fact payloads."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        entries: list[tuple[str, Any]] = [
            (str(key), item) for key, item in cast(dict[Any, Any], value).items()
        ]
        sensitive_markers = ("password", "secret", "token", "community")
        sensitive_keys = {
            key for key, _ in entries if any(marker in key.lower() for marker in sensitive_markers)
        }
        redaction: dict[str, Any]
        if sensitive_keys:
            redaction = {
                key: (REDACTED_REPLACEMENT if key in sensitive_keys else redact_tree(item))
                for key, item in entries
            }
        else:
            redaction = {key: redact_tree(item) for key, item in entries}
        return redaction
    if isinstance(value, list):
        raw_items = cast("list[Any]", value)
        items: list[Any] = [redact_tree(item) for item in raw_items]
        return items
    return value


# --- Signed manifests and bundles --------------------------------------------


def generate_signing_keypair() -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    public_pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def sign_manifest(manifest: dict[str, Any], private_pem: bytes) -> bytes:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = Ed25519PrivateKey.from_private_bytes(_raw_private(private_pem))
    return key.sign(payload)


def verify_manifest(manifest: dict[str, Any], signature: bytes, public_pem: bytes) -> bool:
    try:
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        Ed25519PublicKey.from_public_bytes(_raw_public(public_pem)).verify(signature, payload)
        return True
    except Exception:  # noqa: BLE001 - verification rejects malformed inputs
        return False


def _raw_private(private_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_pem, password=None)
    if isinstance(key, Ed25519PrivateKey):
        return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raise EvidenceError("manifests are signed with the Ed25519 algorithm only")


def _raw_public(public_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(public_pem)
    if isinstance(key, Ed25519PublicKey):
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    raise EvidenceError("manifests verify against an Ed25519 public key only")


def build_file_manifest(files: list[tuple[str, bytes]]) -> dict[str, Any]:
    entries = []
    for path, content in files:
        _validate_bundle_path(path)
        entries.append(
            {
                "path": path,
                "sha256": sha256_hex(content),
                "size_bytes": len(content),
            }
        )
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "entries": entries,
    }


def _validate_bundle_path(path: str) -> None:
    if not path or path.startswith(("/", "\\")) or ":\\\\" in path or ":/" in path:
        raise EvidenceError("bundle paths must be relative without drive letters")
    parts = path.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise EvidenceError("bundle paths must not traverse directories")
    if len(parts) != len(set(parts)):
        raise EvidenceError("bundle paths must be unique")
    if len(path) > 256 or path.endswith("/"):
        raise EvidenceError("bundle path is malformed")
