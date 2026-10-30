"""Linux SSH reader against output captured from a real Ubuntu 24.04 host."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from baselineguard_adapters.linux.ssh import LINUX_READERS, ReadOutput, UbuntuSSHReader
from baselineguard_adapters.orchestrate import normalize_outputs
from baselineguard_contracts.common import FactState

OS_RELEASE = 'NAME="Ubuntu"\nVERSION="24.04.4 LTS (Noble Numbat)"\nID=ubuntu\nVERSION_ID="24.04"\n'


def output(reader_id: str, text: str, exit_code: int = 0) -> tuple[str, ReadOutput]:
    raw = text.encode()
    return reader_id, ReadOutput(
        reader_id=reader_id,
        text=text,
        exit_code=exit_code,
        output_bytes=len(raw),
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )


def facts_by_id(results: list[tuple[str, ReadOutput]]) -> dict[str, Any]:
    return {f.fact_id: f for f in normalize_outputs(results)}


def test_real_ubuntu_output_with_partial_failures_still_normalizes() -> None:
    facts = facts_by_id(
        [
            output("linux.identity.os_release", OS_RELEASE),
            # Unprivileged sshd -T without the sudoers grant: no stdout, non-zero exit.
            output("linux.ssh.effective_config", "", exit_code=1),
            # stat skips a missing file and exits 1; modes print without a leading zero.
            output(
                "linux.files.security_modes",
                "/etc/passwd 644\n/etc/shadow 640\n/var/log/auth.log 640\n",
                exit_code=1,
            ),
            output("linux.auth.umask_defaults", "UMASK\t\t022\n"),
            output("linux.auditd.active", "inactive\n", exit_code=4),
            output("linux.time.ntp_state", "NTPSynchronized=yes\n"),
        ]
    )
    assert facts["platform.family"].value == "ubuntu"
    assert facts["platform.version"].value == "24.04"
    assert facts["auth.ssh.permit_root_login"].state is FactState.UNAVAILABLE
    assert facts["files.etc_shadow.mode"].value == "0640"
    assert facts["files.sshd_config.mode"].state is FactState.UNAVAILABLE
    assert facts["auth.umask.default"].value == 0o22
    assert facts["services.auditd.active"].state is FactState.PRESENT
    assert facts["services.auditd.active"].value is False
    assert facts["services.system_time.synchronized"].value is True


def test_sysctl_values_are_discarded_when_any_key_failed() -> None:
    # A missing key shifts every later value; a misaligned read must not become evidence.
    partial = facts_by_id([output("linux.kernel.security_sysctl", "2\n0\n0\n", exit_code=255)])
    assert all(
        f.state is FactState.UNAVAILABLE for f in partial.values() if f.fact_id != "platform.family"
    )
    complete = facts_by_id(
        [output("linux.kernel.security_sysctl", "2\n0\n0\n0\n0\n0\n0\n1\n")]
    )
    assert complete["kernel.randomize_va_space"].value == 2
    assert complete["net.ipv4.tcp_syncookies"].value == 1


class FakeChannel:
    def __init__(self, stdout: bytes, stderr: bytes, exit_code: int) -> None:
        self._stdout, self._stderr, self._exit = stdout, stderr, exit_code

    def recv_ready(self) -> bool:
        return bool(self._stdout)

    def recv(self, n: int) -> bytes:
        chunk, self._stdout = self._stdout[:n], self._stdout[n:]
        return chunk

    def recv_stderr_ready(self) -> bool:
        return bool(self._stderr)

    def recv_stderr(self, n: int) -> bytes:
        chunk, self._stderr = self._stderr[:n], self._stderr[n:]
        return chunk

    def exit_status_ready(self) -> bool:
        return True

    def recv_exit_status(self) -> int:
        return self._exit


class FakeClient:
    def __init__(self, replies: dict[str, tuple[bytes, bytes, int]]) -> None:
        self.replies = replies

    def exec_command(self, command: str, **_: Any) -> tuple[None, Any, None]:
        channel = FakeChannel(*self.replies[command])
        return None, SimpleNamespace(channel=channel), None


def test_stderr_from_one_reader_does_not_abort_collection(tmp_path: Path) -> None:
    reader = UbuntuSSHReader(known_hosts=tmp_path / "known_hosts")
    client: Any = FakeClient(
        {
            LINUX_READERS["linux.files.security_modes"]: (
                b"/etc/passwd 644\n",
                b"stat: cannot statx '/etc/ssh/sshd_config': No such file or directory\n",
                1,
            ),
        }
    )
    result = reader._read(client, "linux.files.security_modes")  # pyright: ignore[reportPrivateUsage]
    assert result.exit_code == 1
    assert result.text == "/etc/passwd 644\n"


def test_sshd_reader_falls_back_to_a_narrow_sudo_grant() -> None:
    command = LINUX_READERS["linux.ssh.effective_config"]
    assert command.startswith("/usr/sbin/sshd -T 2>/dev/null || ")
    assert command.endswith("/usr/bin/sudo -n /usr/sbin/sshd -T")


def test_legacy_without_password_spelling_is_recognised() -> None:
    # Stock Ubuntu's sshd -T prints the legacy alias; it must be evaluated, not "unknown".
    facts = facts_by_id(
        [output("linux.ssh.effective_config", "permitrootlogin without-password\n")]
    )
    assert facts["auth.ssh.permit_root_login"].state is FactState.PRESENT
    assert facts["auth.ssh.permit_root_login"].value == "prohibit-password"
