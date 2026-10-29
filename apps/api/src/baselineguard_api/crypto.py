"""Authenticated envelope encryption; master key material stays outside PostgreSQL.

The primitive is identical to `baselineguard_credentials.envelope`; this module
keeps the established `binding`-parameter API used by local identity flows.
"""

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _master(path: str) -> bytes:
    material = Path(path).read_bytes()
    if len(material) != 32:
        raise ValueError("Master key must contain exactly 32 bytes")
    return material


def seal(plaintext: bytes, *, binding: str, master_key_file: str) -> bytes:
    aad = binding.encode("utf-8")
    data_key = AESGCM.generate_key(bit_length=256)
    nonce, wrap_nonce = os.urandom(12), os.urandom(12)
    values: dict[str, str | bytes] = {
        "version": "1",
        "nonce": nonce,
        "wrap_nonce": wrap_nonce,
        "ciphertext": AESGCM(data_key).encrypt(nonce, plaintext, aad),
        "wrapped_key": AESGCM(_master(master_key_file)).encrypt(wrap_nonce, data_key, aad),
    }
    return json.dumps(
        {
            k: base64.b64encode(v).decode("ascii") if isinstance(v, bytes) else v
            for k, v in values.items()
        },
        sort_keys=True,
    ).encode("utf-8")


def unseal(envelope: bytes, *, binding: str, master_key_file: str) -> bytes:
    if len(envelope) > 1_048_576:
        raise ValueError("Encrypted envelope exceeds size limit")
    data = json.loads(envelope)
    if (
        set(data) != {"version", "nonce", "wrap_nonce", "ciphertext", "wrapped_key"}
        or data["version"] != "1"
    ):
        raise ValueError("Unsupported encrypted envelope")
    aad = binding.encode("utf-8")
    decoded = {k: base64.b64decode(v, validate=True) for k, v in data.items() if k != "version"}
    key: bytes = AESGCM(_master(master_key_file)).decrypt(
        decoded["wrap_nonce"], decoded["wrapped_key"], aad
    )
    return AESGCM(key).decrypt(decoded["nonce"], decoded["ciphertext"], aad)
