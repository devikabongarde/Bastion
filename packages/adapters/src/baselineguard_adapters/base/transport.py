from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import paramiko


class TargetScopeError(ValueError):
    pass


type SocketAddress = tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]
type AddressInfo = tuple[int, int, int, str, SocketAddress]


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    original_host: str
    connect_ip: str
    port: int


def _is_forbidden_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_global is False
        and address.is_private is False
    )


def resolve_authorized_endpoint(
    host: str,
    port: int,
    *,
    allowed_cidrs: tuple[str, ...],
    allowed_dns_suffixes: tuple[str, ...],
    allowed_ports: tuple[int, ...],
    resolver: Callable[..., Sequence[AddressInfo]] = socket.getaddrinfo,
    allow_loopback: bool = False,
) -> ResolvedEndpoint:
    """Resolve once, authorize every answer, and return a pinned address for the socket."""
    if port not in allowed_ports:
        raise TargetScopeError("TARGET_PORT_OUT_OF_SCOPE")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        normalized = host.rstrip(".").lower()
        suffix_ok = any(
            normalized == suffix.lstrip(".").rstrip(".").lower()
            or normalized.endswith("." + suffix.lstrip(".").rstrip(".").lower())
            for suffix in allowed_dns_suffixes
        )
        if not suffix_ok:
            raise TargetScopeError("TARGET_NAME_OUT_OF_SCOPE") from None
        try:
            records: Sequence[AddressInfo] = resolver(normalized, port, type=socket.SOCK_STREAM)
        except OSError:
            raise TargetScopeError("TARGET_NAME_RESOLUTION_FAILED") from None
        addresses = sorted(
            {ipaddress.ip_address(record[4][0]) for record in records},
            key=lambda item: (item.version, int(item)),
        )
    else:
        addresses = [literal]
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs]
    if not addresses:
        raise TargetScopeError("TARGET_NAME_RESOLUTION_FAILED")
    if any(
        _is_forbidden_ip(address) and not (allow_loopback and address.is_loopback)
        for address in addresses
    ):
        raise TargetScopeError("TARGET_ADDRESS_PROHIBITED")
    if any(
        not any(address.version == network.version and address in network for network in networks)
        for address in addresses
    ):
        raise TargetScopeError("TARGET_ADDRESS_OUT_OF_SCOPE")
    return ResolvedEndpoint(original_host=host, connect_ip=str(addresses[0]), port=port)


@dataclass(frozen=True, slots=True)
class SSHCredential:
    username: str
    private_key: paramiko.PKey | None = None
    password: str | None = None

    def __post_init__(self) -> None:
        if not self.username or (self.private_key is None) == (self.password is None):
            raise ValueError("SSH credentials require exactly one authentication method")


def make_strict_ssh_client(known_hosts: Path):
    import paramiko

    if not known_hosts.is_file():
        raise FileNotFoundError("The configured SSH known_hosts file is missing.")
    client = paramiko.SSHClient()
    client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return client


def pinned_socket(endpoint: ResolvedEndpoint, timeout_seconds: int) -> socket.socket:
    """Connect to the already-authorized IP without resolving the host a second time."""
    return socket.create_connection((endpoint.connect_ip, endpoint.port), timeout=timeout_seconds)
