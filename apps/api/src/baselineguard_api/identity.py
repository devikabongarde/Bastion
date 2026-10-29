"""Local password and RFC 6238 TOTP primitives without an external service."""

import base64
import hashlib
import hmac
import secrets
import struct
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
# Fixed non-user credential for approximately uniform missing-account password work.
DUMMY_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))


def hash_password(password: str, blocklist: str | None = None) -> str:
    if not 14 <= len(password) <= 1024:
        raise ValueError("Use a password of 14 through 1024 characters")
    if blocklist:
        with Path(blocklist).open(encoding="utf-8") as stream:
            if any(password.casefold() == line.rstrip("\r\n").casefold() for line in stream):
                raise ValueError(
                    "Choose a password absent from the configured blocked-password list"
                )
    return PASSWORD_HASHER.hash(password)


def verify_password(encoded: str | None, password: str) -> bool:
    try:
        valid = PASSWORD_HASHER.verify(encoded or DUMMY_HASH, password)
        return bool(encoded and valid)
    except (VerificationError, InvalidHashError):
        return False


def new_totp_secret() -> bytes:
    return secrets.token_bytes(20)


def encoded_totp_secret(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def totp_code(secret: bytes, step: int, *, digits: int = 6) -> str:
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def verify_totp(secret: bytes, code: str, *, timestamp: float, last_step: int) -> int | None:
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int(timestamp // 30)
    for step in (current, current - 1, current + 1):
        if step >= 0 and step > last_step and hmac.compare_digest(totp_code(secret, step), code):
            return step
    return None


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def recovery_hash(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def new_recovery_codes() -> tuple[list[str], list[str]]:
    codes = [secrets.token_hex(10).upper() for _ in range(10)]
    return codes, [recovery_hash(code) for code in codes]
