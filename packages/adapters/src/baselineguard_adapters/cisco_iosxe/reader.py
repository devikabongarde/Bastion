from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path

import paramiko

from baselineguard_adapters.base.transport import (
    ResolvedEndpoint,
    SSHCredential,
    make_strict_ssh_client,
    pinned_socket,
)
from baselineguard_adapters.linux.ssh import CollectionError, ReadOutput

MAX_READER_BYTES = 1_048_576
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
PROMPT = re.compile(r"(?m)^[A-Za-z0-9_.:/()@-]{1,128}[>#]\s*$")
ERROR_MARKERS = (
    "% invalid input",
    "% authorization failed",
    "command authorization failed",
    "% incomplete command",
    "% ambiguous command",
)
SECRET_LINE = re.compile(
    r"(?i)^\s*(?:"
    r"username\s+\S+.*\b(?:password|secret)\b|"
    r"(?:enable\s+)?(?:password|secret)\b|"
    r"snmp-server\s+community\b|"
    r"snmp-server\s+user\b|"
    r".*\b(?:authentication-key|privacy-key|key-string|pre-shared-key)\b"
    r")"
)

IOSXE_READERS: dict[str, str] = {
    "iosxe.identity.show_version": "show version",
    "iosxe.config.running": "show running-config",
    "iosxe.time.clock": "show clock",
    "iosxe.switch.interfaces_switchport": "show interfaces switchport",
    "iosxe.switch.spanning_tree": "show spanning-tree summary",
    "iosxe.switch.port_security": "show port-security",
    "iosxe.switch.vlans_brief": "show vlan brief",
}
IOSXE_ROUTER_READERS = ("iosxe.interfaces.ip_brief", "show ip interface brief")
IOSXE_SWITCH_READERS = (
    ("iosxe.switch.interfaces_switchport", "show interfaces switchport"),
    ("iosxe.switch.spanning_tree", "show spanning-tree summary"),
    ("iosxe.switch.port_security", "show port-security"),
    ("iosxe.switch.vlans_brief", "show vlan brief"),
)


@dataclass(frozen=True, slots=True)
class CiscoIOSXECollection:
    role: str
    reader_outputs: tuple[ReadOutput, ...]
    session_side_effects: tuple[str, ...] = ("terminal length 0", "terminal width 511")


def redact_cisco_config(value: str) -> str:
    """Mask line and certificate secrets before a configuration leaves the collector."""
    redacted: list[str] = []
    in_certificate = False
    for line in value.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("crypto pki certificate chain"):
            in_certificate = True
            redacted.append("<redacted certificate block>")
            continue
        if in_certificate:
            if stripped == "quit":
                in_certificate = False
            continue
        if SECRET_LINE.search(line):
            redacted.append("<redacted secret-bearing configuration line>")
        else:
            redacted.append(line)
    return "\n".join(redacted)


class CiscoIOSXEReader:
    """Read-only IOS XE CLI adapter with pinned host identity and fixed show commands."""

    def __init__(
        self,
        *,
        known_hosts: Path,
        role: str,
        timeout_seconds: int = 15,
        max_bytes: int = MAX_READER_BYTES,
    ) -> None:
        if role not in {"router", "switch"}:
            raise ValueError("IOS XE role must be router or switch")
        if not 1 <= timeout_seconds <= 60 or not 1024 <= max_bytes <= MAX_READER_BYTES:
            raise ValueError("Reader bounds are outside their allowed range")
        self.known_hosts = known_hosts
        self.role = role
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def collect(
        self,
        endpoint: ResolvedEndpoint,
        credential: SSHCredential,
    ) -> CiscoIOSXECollection:
        client = make_strict_ssh_client(self.known_hosts)
        try:
            client.connect(
                hostname=endpoint.original_host,
                sock=pinned_socket(endpoint, self.timeout_seconds),
                port=endpoint.port,
                username=credential.username,
                pkey=credential.private_key,
                password=credential.password if credential.private_key is None else None,
                timeout=self.timeout_seconds,
                banner_timeout=self.timeout_seconds,
                auth_timeout=self.timeout_seconds,
                allow_agent=False,
                look_for_keys=False,
            )
            channel = client.invoke_shell(term="vt100", width=200, height=1000)
            channel.settimeout(0.2)
            self._read_prompt(channel)
            # These are session-local terminal display settings, not device configuration.
            self._send_command(channel, "terminal length 0")
            self._send_command(channel, "terminal width 511")
            readers = list(IOSXE_READERS.items())
            if self.role == "router":
                readers.append(IOSXE_ROUTER_READERS)
            else:
                readers.extend(IOSXE_SWITCH_READERS)
            outputs = tuple(
                self._collect_one(channel, reader_id, command) for reader_id, command in readers
            )
            return CiscoIOSXECollection(role=self.role, reader_outputs=outputs)
        except paramiko.BadHostKeyException:
            raise CollectionError("SSH_HOST_KEY_MISMATCH") from None
        except paramiko.AuthenticationException:
            raise CollectionError("SSH_AUTHENTICATION_FAILED") from None
        except (TimeoutError, paramiko.SSHException, OSError):
            raise CollectionError("SSH_COLLECTION_FAILED") from None
        finally:
            client.close()

    def _send_command(self, channel: paramiko.Channel, command: str) -> str:
        allowed = set(IOSXE_READERS.values()) | {
            IOSXE_ROUTER_READERS[1],
            *(value for _, value in IOSXE_SWITCH_READERS),
            "terminal length 0",
            "terminal width 511",
        }
        if command not in allowed:
            raise CollectionError("READER_NOT_ALLOWED")
        channel.sendall((command + "\n").encode("ascii"))
        return self._read_prompt(channel)

    def _read_prompt(self, channel: paramiko.Channel) -> str:
        chunks = bytearray()
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            try:
                if channel.recv_ready():
                    chunks.extend(channel.recv(64 * 1024))
                    if len(chunks) > self.max_bytes:
                        raise CollectionError("OUTPUT_LIMIT_EXCEEDED")
                    clean = ANSI_ESCAPE.sub("", chunks.decode("utf-8", errors="replace"))
                    if "--More--" in clean or " --More--" in clean:
                        raise CollectionError("OUTPUT_PAGINATION_DETECTED")
                    match = PROMPT.search(clean.rstrip())
                    if match:
                        output = clean[: match.start()]
                        lowered = output.lower()
                        if any(marker in lowered for marker in ERROR_MARKERS):
                            raise CollectionError("DEVICE_REJECTED_READ_COMMAND")
                        return output
                else:
                    time.sleep(0.01)
            except TimeoutError:
                time.sleep(0.01)
        raise CollectionError("READER_TIMEOUT")

    def _collect_one(self, channel: paramiko.Channel, reader_id: str, command: str) -> ReadOutput:
        output = self._send_command(channel, command)
        lines = output.replace("\r\n", "\n").replace("\r", "\n").splitlines()
        if lines and lines[0].strip() == command:
            lines = lines[1:]
        clean = "\n".join(lines).strip("\n")
        if reader_id == "iosxe.config.running":
            clean = redact_cisco_config(clean)
        encoded = clean.encode("utf-8")
        if len(encoded) > self.max_bytes:
            raise CollectionError("OUTPUT_LIMIT_EXCEEDED")
        return ReadOutput(
            reader_id=reader_id,
            text=clean,
            exit_code=0,
            output_bytes=len(encoded),
            source_sha256=hashlib.sha256(encoded).hexdigest(),
        )
