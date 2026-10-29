from __future__ import annotations

import hashlib
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

MAX_READER_BYTES = 1_048_576
LINUX_READERS: dict[str, str] = {
    "linux.identity.uname": "/usr/bin/uname -srm",
    "linux.identity.os_release": "/usr/bin/cat /etc/os-release",
    "linux.ssh.effective_config": "/usr/sbin/sshd -T",
    "linux.kernel.security_sysctl": (
        "/usr/sbin/sysctl -n kernel.randomize_va_space fs.suid_dumpable "
        "net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects "
        "net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.send_redirects "
        "net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies"
    ),
    "linux.files.security_modes": (
        "/usr/bin/stat -c '%n %a' /etc/passwd /etc/shadow "
        "/etc/ssh/sshd_config /var/log/auth.log"
    ),
    "linux.auth.umask_defaults": "/bin/grep -E '^UMASK' /etc/login.defs",
    "linux.auditd.active": "/usr/bin/systemctl is-active auditd",
    "linux.time.ntp_state": "/usr/bin/timedatectl show -p NTPSynchronized",
}


class CollectionError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ReadOutput:
    reader_id: str
    text: str
    exit_code: int
    output_bytes: int
    source_sha256: str


class UbuntuSSHReader:
    """Fixed read-only Ubuntu readers; no caller-supplied command text is accepted."""

    def __init__(
        self, *, known_hosts: Path, timeout_seconds: int = 10, max_bytes: int = MAX_READER_BYTES
    ):
        if not 1 <= timeout_seconds <= 30 or not 1024 <= max_bytes <= MAX_READER_BYTES:
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
            or len(reader_ids) > len(LINUX_READERS)
            or len(set(reader_ids)) != len(reader_ids)
        ):
            raise CollectionError("INVALID_READER_SET")
        if any(reader_id not in LINUX_READERS for reader_id in reader_ids):
            raise CollectionError("READER_NOT_ALLOWED")
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
                outputs.append(self._read(client, reader_id))
            return tuple(outputs)
        except paramiko.BadHostKeyException:
            raise CollectionError("SSH_HOST_KEY_MISMATCH") from None
        except paramiko.AuthenticationException:
            raise CollectionError("SSH_AUTHENTICATION_FAILED") from None
        except (TimeoutError, paramiko.SSHException, OSError):
            raise CollectionError("SSH_COLLECTION_FAILED") from None
        finally:
            client.close()

    def _read(self, client: paramiko.SSHClient, reader_id: str) -> ReadOutput:
        _stdin, stdout, _stderr = client.exec_command(
            LINUX_READERS[reader_id],
            timeout=self.timeout_seconds,
            get_pty=False,
        )
        try:
            channel = stdout.channel
            output = bytearray()
            error_output = bytearray()
            deadline = time.monotonic() + self.timeout_seconds
            while True:
                if channel.recv_ready():
                    output.extend(channel.recv(min(64 * 1024, self.max_bytes + 1 - len(output))))
                if channel.recv_stderr_ready():
                    error_output.extend(
                        channel.recv_stderr(min(64 * 1024, 64 * 1024 + 1 - len(error_output)))
                    )
                if len(output) > self.max_bytes or len(error_output) > 64 * 1024:
                    raise CollectionError("OUTPUT_LIMIT_EXCEEDED")
                if (
                    channel.exit_status_ready()
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                ):
                    break
                if time.monotonic() >= deadline:
                    raise CollectionError("READER_TIMEOUT")
                time.sleep(0.005)
            exit_code = channel.recv_exit_status()
            if error_output:
                raise CollectionError("READER_REPORTED_ERROR")
            text_value = bytes(output).decode("utf-8", errors="strict")
            return ReadOutput(
                reader_id=reader_id,
                text=text_value,
                exit_code=exit_code,
                output_bytes=len(output),
                source_sha256=hashlib.sha256(output).hexdigest(),
            )
        except UnicodeDecodeError:
            raise CollectionError("OUTPUT_ENCODING_UNSUPPORTED") from None
        except TimeoutError:
            raise CollectionError("READER_TIMEOUT") from None
