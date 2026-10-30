"""Remote Windows collection reuses the SSH reader with the Windows command table."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from baselineguard_adapters.windows.reader import WINDOWS_READERS
from baselineguard_adapters.windows.ssh import WindowsSSHReader
from tests.unit.test_linux_reader import FakeClient


def test_windows_ssh_reader_runs_only_the_windows_command_table(tmp_path: Path) -> None:
    reader = WindowsSSHReader(known_hosts=tmp_path / "known_hosts")
    assert reader.readers is WINDOWS_READERS
    assert reader.timeout_seconds == 30
    command = WINDOWS_READERS["windows.audit.auditpol"]
    client: Any = FakeClient({command: (b"Machine Name,Policy Target\r\n", b"", 0)})
    result = reader._read(client, "windows.audit.auditpol")  # pyright: ignore[reportPrivateUsage]
    assert result.text.startswith("Machine Name")


def test_windows_console_code_page_output_is_decoded_not_rejected(tmp_path: Path) -> None:
    reader = WindowsSSHReader(known_hosts=tmp_path / "known_hosts")
    # 0x82 is "é" in the OEM code page and invalid as UTF-8.
    assert reader._decode(b"Caf\x82") == "Café"  # pyright: ignore[reportPrivateUsage]
    assert reader._decode("Café".encode()) == "Café"  # pyright: ignore[reportPrivateUsage]
