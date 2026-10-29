from __future__ import annotations

import hashlib
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

FORTIGATE_READERS: dict[str, str] = {
    "fortigate.identity.status": "get system status",
    "fortigate.system.global": "get system global",
    "fortigate.admin.settings": "get system admin settings",
    "fortigate.firewall.policy": "show firewall policy",
    "fortigate.system.interface": "get system interface",
    "fortigate.log.syslog": "get log syslogd setting",
}


class FortiGateReader:
    """Read-only FortiOS command adapter over SSH/CLI."""

    def __init__(
        self,
        *,
        known_hosts: Path | None = None,
        timeout_seconds: int = 15,
        max_bytes: int = MAX_READER_BYTES,
    ):
        if not 1 <= timeout_seconds <= 60 or not 1024 <= max_bytes <= MAX_READER_BYTES:
            raise ValueError("Reader bounds are outside their allowed range")
        self.known_hosts = known_hosts
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def collect(
        self,
        endpoint: ResolvedEndpoint,
        credential: SSHCredential,
        reader_ids: tuple[str, ...],
    ) -> tuple[ReadOutput, ...]:
        if (
            not reader_ids
            or len(reader_ids) > len(FORTIGATE_READERS)
            or len(set(reader_ids)) != len(reader_ids)
        ):
            raise CollectionError("INVALID_READER_SET")
        if any(reader_id not in FORTIGATE_READERS for reader_id in reader_ids):
            raise CollectionError("READER_NOT_ALLOWED")

        if self.known_hosts is None:
            raise CollectionError("KNOWN_HOSTS_REQUIRED")

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
            outputs: list[ReadOutput] = []
            for reader_id in reader_ids:
                cmd = FORTIGATE_READERS[reader_id]
                stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout_seconds)
                raw_bytes = stdout.read(self.max_bytes + 1)
                if len(raw_bytes) > self.max_bytes:
                    raise CollectionError("READER_OUTPUT_LIMIT_EXCEEDED")
                exit_code = stdout.channel.recv_exit_status()
                text = raw_bytes.decode("utf-8", errors="replace")
                digest = hashlib.sha256(raw_bytes).hexdigest()
                outputs.append(
                    ReadOutput(
                        reader_id=reader_id,
                        text=text,
                        exit_code=exit_code,
                        output_bytes=len(raw_bytes),
                        source_sha256=digest,
                    )
                )
            return tuple(outputs)
        except paramiko.BadHostKeyException:
            raise CollectionError("SSH_HOST_KEY_MISMATCH") from None
        except paramiko.AuthenticationException:
            raise CollectionError("SSH_AUTHENTICATION_FAILED") from None
        except Exception as e:
            if isinstance(e, CollectionError):
                raise
            raise CollectionError(f"FORTIGATE_TRANSPORT_ERROR: {e}") from None
        finally:
            client.close()
