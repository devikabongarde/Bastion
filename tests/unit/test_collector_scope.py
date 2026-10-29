import socket

import pytest
from baselineguard_adapters.base.transport import (
    ResolvedEndpoint,
    SSHCredential,
    TargetScopeError,
    resolve_authorized_endpoint,
)
from baselineguard_adapters.cisco_iosxe.reader import redact_cisco_config


def _record(address: str) -> tuple[int, int, int, str, tuple[str, int]]:
    return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 22)


def test_dns_resolution_authorizes_every_answer_and_pins_one_address() -> None:
    calls: list[tuple[str, int]] = []

    def resolver(host: str, port: int, *, type: int) -> list[tuple]:
        calls.append((host, port))
        return [_record("10.1.2.3"), _record("10.1.2.4")]

    endpoint = resolve_authorized_endpoint(
        "router.lab.example",
        22,
        allowed_cidrs=("10.1.2.0/24",),
        allowed_dns_suffixes=("lab.example",),
        allowed_ports=(22,),
        resolver=resolver,
    )
    assert endpoint == ResolvedEndpoint("router.lab.example", "10.1.2.3", 22)
    assert calls == [("router.lab.example", 22)]


def test_dns_rebinding_or_mixed_scope_answers_are_rejected() -> None:
    def resolver(host: str, port: int, *, type: int) -> list[tuple]:
        return [_record("10.1.2.3"), _record("203.0.113.9")]

    with pytest.raises(
        TargetScopeError,
        match="TARGET_ADDRESS_PROHIBITED|TARGET_ADDRESS_OUT_OF_SCOPE",
    ):
        resolve_authorized_endpoint(
            "router.lab.example",
            22,
            allowed_cidrs=("10.1.2.0/24",),
            allowed_dns_suffixes=("lab.example",),
            allowed_ports=(22,),
            resolver=resolver,
        )


def test_address_must_match_site_suffix_and_management_port() -> None:
    with pytest.raises(TargetScopeError, match="TARGET_NAME_OUT_OF_SCOPE"):
        resolve_authorized_endpoint(
            "attacker.example",
            22,
            allowed_cidrs=("10.1.2.0/24",),
            allowed_dns_suffixes=("lab.example",),
            allowed_ports=(22,),
        )
    with pytest.raises(TargetScopeError, match="TARGET_PORT_OUT_OF_SCOPE"):
        resolve_authorized_endpoint(
            "10.1.2.3",
            3389,
            allowed_cidrs=("10.1.2.0/24",),
            allowed_dns_suffixes=(),
            allowed_ports=(22,),
        )


def test_credentials_do_not_mix_key_and_password_fallback() -> None:
    assert SSHCredential(username="auditor", password="one-use-secret")
    with pytest.raises(ValueError, match="exactly one"):
        SSHCredential(username="auditor", password="one-use-secret", private_key=object())  # type: ignore[arg-type]


def test_cisco_configuration_secrets_are_redacted_before_export() -> None:
    config = """hostname router
snmp-server community public RO
username operator privilege 15 secret 9 hash-value
crypto pki certificate chain SELF
  certificate ca 01
  ABCDEF
quit
interface GigabitEthernet1
 description uplink
"""
    output = redact_cisco_config(config)
    assert "public RO" not in output
    assert "hash-value" not in output
    assert "ABCDEF" not in output
    assert "description uplink" in output
