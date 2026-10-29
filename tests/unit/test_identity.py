from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from baselineguard_api.crypto import seal, unseal
from baselineguard_api.identity import hash_password, totp_code, verify_password, verify_totp
from baselineguard_api.security import Principal


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ],
)
def test_totp_matches_rfc6238_sha1_vectors(seconds, expected):
    assert totp_code(b"12345678901234567890", seconds // 30, digits=8) == expected


def test_totp_replay_and_window_are_rejected():
    secret = b"12345678901234567890"
    code = totp_code(secret, 100)
    assert verify_totp(secret, code, timestamp=3000, last_step=99) == 100
    assert verify_totp(secret, code, timestamp=3000, last_step=100) is None
    assert verify_totp(secret, code, timestamp=3120, last_step=-1) is None


def test_password_policy_and_verification(tmp_path):
    with pytest.raises(ValueError):
        hash_password("short")
    path = tmp_path / "blocked.txt"
    path.write_text("blocked test password\n", encoding="utf-8")
    with pytest.raises(ValueError):
        hash_password("blocked test password", str(path))
    encoded = hash_password("a long test passphrase")
    assert verify_password(encoded, "a long test passphrase")
    assert not verify_password(encoded, "another passphrase")
    assert not verify_password(None, "a long test passphrase")


def test_envelope_binds_ciphertext_to_org_object_and_type(tmp_path):
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    encrypted = seal(b"secret canary", binding="org/object/totp", master_key_file=str(key))
    assert b"secret canary" not in encrypted
    assert (
        unseal(encrypted, binding="org/object/totp", master_key_file=str(key)) == b"secret canary"
    )
    with pytest.raises(InvalidTag):
        unseal(encrypted, binding="other/object/totp", master_key_file=str(key))
    assert encrypted != seal(b"secret canary", binding="org/object/totp", master_key_file=str(key))


def test_role_bindings_do_not_union_permissions_across_sites():
    site_a, site_b = uuid4(), uuid4()
    principal = Principal(
        uuid4(),
        uuid4(),
        frozenset({"viewer", "scan_operator"}),
        frozenset({site_a, site_b}),
        bindings=(("viewer", site_a), ("scan_operator", site_b)),
    )
    assert principal.sites_for({"scan_operator"}) == frozenset({site_b})
    assert principal.sites_for({"viewer"}) == frozenset({site_a})
    assert principal.sites_for({"credential_admin"}) == frozenset()
