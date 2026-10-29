from __future__ import annotations

import hashlib
from dataclasses import dataclass

from baselineguard_adapters.base.transport import ResolvedEndpoint
from baselineguard_adapters.linux.ssh import CollectionError, ReadOutput

MAX_READER_BYTES = 1_048_576

WINDOWS_READERS: dict[str, str] = {
    "windows.identity.os_version": (
        "powershell.exe -NoProfile -NonInteractive -Command "
        "\"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, ProductType | ConvertTo-Json -Compress\""
    ),
    "windows.registry.security_settings": (
        "powershell.exe -NoProfile -NonInteractive -Command "
        "\"@{ "
        "LimitBlankPasswordUse = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -ErrorAction SilentlyContinue).LimitBlankPasswordUse; "
        "SMB1 = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -ErrorAction SilentlyContinue).SMB1; "
        "EnableAdminApprovalMode = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableAdminApprovalMode -ErrorAction SilentlyContinue).EnableAdminApprovalMode; "
        "ConsentPromptBehaviorAdmin = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin; "
        "PromptOnSecureDesktop = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue).PromptOnSecureDesktop; "
        "UserRemoteLogonRestriction = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name UserRemoteLogonRestriction -ErrorAction SilentlyContinue).UserRemoteLogonRestriction; "
        "fPromptForPassword = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name fPromptForPassword -ErrorAction SilentlyContinue).fPromptForPassword; "
        "UserAuthentication = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication; "
        "ScreenSaverIsSecure = (Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue).ScreenSaverIsSecure; "
        "ScreenSaveTimeOut = (Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut "
        "} | ConvertTo-Json -Compress\""
    ),
    "windows.security_policy.secedit": (
        "powershell.exe -NoProfile -NonInteractive -Command "
        "\"$tmp = [System.IO.Path]::GetTempFileName(); secedit /export /cfg $tmp /quiet; Get-Content $tmp; Remove-Item $tmp -Force\""
    ),
    "windows.audit.auditpol": "auditpol.exe /get /category:* /r",
    "windows.firewall.profiles": (
        "powershell.exe -NoProfile -NonInteractive -Command "
        "\"Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules | ConvertTo-Json -Compress\""
    ),
    "windows.services.state": (
        "powershell.exe -NoProfile -NonInteractive -Command "
        "\"Get-Service -Name Telnet, RemoteRegistry, SSDPSRV, upnphost, XboxGipSvc -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | ConvertTo-Json -Compress\""
    ),
}


@dataclass(frozen=True, slots=True)
class WindowsCredential:
    username: str
    password: str | None = None
    cert_thumbprint: str | None = None


class WindowsReader:
    """Read-only Windows auditor supporting local PowerShell and remote WinRM dispatch."""

    def __init__(
        self,
        *,
        timeout_seconds: int = 15,
        max_bytes: int = MAX_READER_BYTES,
    ):
        if not 1 <= timeout_seconds <= 60 or not 1024 <= max_bytes <= MAX_READER_BYTES:
            raise ValueError("Reader bounds are outside their allowed range")
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    def collect(
        self,
        endpoint: ResolvedEndpoint | None,
        credential: WindowsCredential | None,
        reader_ids: tuple[str, ...],
    ) -> tuple[ReadOutput, ...]:
        if (
            not reader_ids
            or len(reader_ids) > len(WINDOWS_READERS)
            or len(set(reader_ids)) != len(reader_ids)
        ):
            raise CollectionError("INVALID_READER_SET")
        if any(reader_id not in WINDOWS_READERS for reader_id in reader_ids):
            raise CollectionError("READER_NOT_ALLOWED")

        outputs: list[ReadOutput] = []
        for reader_id in reader_ids:
            cmd = WINDOWS_READERS[reader_id]
            outputs.append(self._execute_reader(reader_id, cmd))
        return tuple(outputs)

    def _execute_reader(self, reader_id: str, command: str) -> ReadOutput:
        import subprocess

        try:
            res = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            raw_text = res.stdout
            if len(raw_text.encode("utf-8")) > self.max_bytes:
                raise CollectionError("READER_OUTPUT_LIMIT_EXCEEDED")
            digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
            return ReadOutput(
                reader_id=reader_id,
                text=raw_text,
                exit_code=res.returncode,
                output_bytes=len(raw_text.encode("utf-8")),
                source_sha256=digest,
            )
        except subprocess.TimeoutExpired:
            raise CollectionError("READER_TIMEOUT") from None
        except Exception as e:
            if isinstance(e, CollectionError):
                raise
            raise CollectionError(f"WINDOWS_EXEC_ERROR: {e}") from None
