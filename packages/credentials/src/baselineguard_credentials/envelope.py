from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_ENVELOPE_BYTES = 1_048_576


class CredentialError(ValueError):
    pass


def _master(master_key_file: str | Path) -> bytes:
    material = Path(master_key_file).read_bytes()
    if len(material) != 32:
        raise CredentialError("master key must contain exactly 32 bytes")
    return material


def _binding(org_id: str, object_id: str, object_type: str = "credential") -> bytes:
    return f"org:{org_id}:type:{object_type}:id:{object_id}".encode()


def seal(plaintext: bytes, *, binding: bytes, master_key_file: str | Path) -> bytes:
    """AEAD envelope primitive; callers derive the context binding themselves."""
    if not plaintext:
        raise CredentialError("empty secret material")
    data_key = AESGCM.generate_key(bit_length=256)
    nonce, wrap_nonce = os.urandom(12), os.urandom(12)
    values: dict[str, str | bytes] = {
        "version": "1",
        "key_version": "master-v1",
        "nonce": nonce,
        "wrap_nonce": wrap_nonce,
        "ciphertext": AESGCM(data_key).encrypt(nonce, plaintext, binding),
        "wrapped_key": AESGCM(_master(master_key_file)).encrypt(wrap_nonce, data_key, binding),
    }
    return json.dumps(
        {
            key: base64.b64encode(value).decode("ascii") if isinstance(value, bytes) else value
            for key, value in values.items()
        },
        sort_keys=True,
    ).encode("utf-8")


def unseal(envelope: bytes, *, binding: bytes, master_key_file: str | Path) -> bytes:
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise CredentialError("encrypted envelope exceeds the size limit")
    try:
        data = json.loads(envelope)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CredentialError("UNSUPPORTED_ENVELOPE") from None
    keys = {"version", "key_version", "nonce", "wrap_nonce", "ciphertext", "wrapped_key"}
    if set(data) != keys or data.get("version") != "1" or data.get("key_version") != "master-v1":
        raise CredentialError("UNSUPPORTED_ENVELOPE")
    try:
        decoded = {
            key: base64.b64decode(data[key], validate=True)
            for key in ("nonce", "wrap_nonce", "wrapped_key", "ciphertext")
        }
        data_key: bytes = AESGCM(_master(master_key_file)).decrypt(
            decoded["wrap_nonce"], decoded["wrapped_key"], binding
        )
        return AESGCM(data_key).decrypt(decoded["nonce"], decoded["ciphertext"], binding)
    except (ValueError, KeyError):
        raise CredentialError("CREDENTIAL_DECRYPT_FAILED") from None
    except Exception as error:  # noqa: BLE001 - AEAD InvalidTag path
        raise CredentialError("CREDENTIAL_DECRYPT_FAILED") from error


def seal_credential(
    plaintext: bytes,
    *,
    org_id: str,
    credential_id: str,
    master_key_file: str | Path,
) -> bytes:
    return seal(
        plaintext,
        binding=_binding(org_id, credential_id),
        master_key_file=master_key_file,
    )


def unseal_credential(
    envelope: bytes,
    *,
    org_id: str,
    credential_id: str,
    master_key_file: str | Path,
) -> bytes:
    return unseal(
        envelope,
        binding=_binding(org_id, credential_id),
        master_key_file=master_key_file,
    )


class CredentialBroker:
    """Job-scoped material delivery helper.

    The broker decrypts material strictly for one (org, credential) pair and
    never logs or persists the plaintext. Job/lease scoping is enforced by the
    caller; remote collectors extend this flow per PRD 14.4.
    """

    def __init__(self, master_key_file: str | Path):
        self.master_key_file = master_key_file

    def release(
        self,
        envelope: bytes,
        *,
        org_id: str,
        credential_id: str,
        purpose: str,
    ) -> dict[str, str]:
        del purpose  # callers enforce purpose binding before release
        plaintext = unseal_credential(
            envelope,
            org_id=org_id,
            credential_id=credential_id,
            master_key_file=self.master_key_file,
        )
        return json.loads(plaintext)