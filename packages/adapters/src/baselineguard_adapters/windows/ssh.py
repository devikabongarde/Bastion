"""Remote Windows collection over the built-in Windows OpenSSH Server.

Runs exactly the same fixed read-only command table as the local Windows reader
(`WINDOWS_READERS`), so the same normalizer and rule pack apply. The account must be a
local administrator: `secedit /export` and `auditpol` need an elevated token, which
Windows OpenSSH grants to administrators.
"""

from __future__ import annotations

from pathlib import Path

from baselineguard_adapters.linux.ssh import MAX_READER_BYTES, UbuntuSSHReader
from baselineguard_adapters.windows.reader import WINDOWS_READERS


class WindowsSSHReader(UbuntuSSHReader):
    readers = WINDOWS_READERS

    def __init__(
        self, *, known_hosts: Path, timeout_seconds: int = 30, max_bytes: int = MAX_READER_BYTES
    ):
        # Each reader starts PowerShell on the target, which is slower than a Linux command.
        super().__init__(
            known_hosts=known_hosts, timeout_seconds=timeout_seconds, max_bytes=max_bytes
        )

    def _decode(self, raw: bytes) -> str:
        # Windows console output is UTF-8 only when configured; otherwise it is the OEM
        # code page. Fall back rather than discard an otherwise valid read.
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("cp437")
