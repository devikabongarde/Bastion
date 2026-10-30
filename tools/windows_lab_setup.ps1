# Prepare a Windows 10/11 PC to be audited by Bastion over SSH.
#
#   Run in PowerShell **as Administrator**:
#   powershell -ExecutionPolicy Bypass -File windows_lab_setup.ps1 [-AuditUser bastionaudit]
#
# Installs and starts the built-in Windows OpenSSH Server, opens TCP 22 in Windows Firewall,
# and creates a local audit account in the Administrators group (secedit and auditpol need
# an elevated token, which Windows OpenSSH gives administrators). Bastion only runs a fixed
# set of read-only commands. Safe to re-run. Undo with -Remove.
param(
    [string]$AuditUser = "bastionaudit",
    [switch]$Remove
)
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this from PowerShell opened with 'Run as administrator'."
}

if ($Remove) {
    Write-Host "Removing Bastion audit access"
    if (Get-LocalUser -Name $AuditUser -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $AuditUser }
    Get-NetFirewallRule -Name "Bastion-SSH-In" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Stop-Service sshd -ErrorAction SilentlyContinue
    Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "Done. (OpenSSH Server stays installed but stopped and disabled.)"
    return
}

Write-Host "[1/4] Installing OpenSSH Server (can take a few minutes the first time)"
$capability = Get-WindowsCapability -Online -Name "OpenSSH.Server*" | Select-Object -First 1
if ($capability.State -ne "Installed") {
    Add-WindowsCapability -Online -Name $capability.Name | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd

Write-Host "[2/4] Allowing inbound SSH (TCP 22) in Windows Firewall"
if (-not (Get-NetFirewallRule -Name "Bastion-SSH-In" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "Bastion-SSH-In" -DisplayName "Bastion audit SSH (TCP 22)" `
        -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null
}

Write-Host "[3/4] Creating local audit account '$AuditUser'"
if (Get-LocalUser -Name $AuditUser -ErrorAction SilentlyContinue) {
    Write-Host "  account exists, leaving its password unchanged"
} else {
    $password = Read-Host -AsSecureString "  Choose a password for $AuditUser (you will enter it in Bastion)"
    New-LocalUser -Name $AuditUser -Password $password -FullName "Bastion audit" `
        -Description "Read-only configuration audit over SSH" -PasswordNeverExpires | Out-Null
}
if (-not (Get-LocalGroupMember -Group "Administrators" -Member $AuditUser -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group "Administrators" -Member $AuditUser
}

Write-Host "[4/4] Details to enter in Bastion"
$ips = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
    ForEach-Object { "$($_.IPAddress) ($($_.InterfaceAlias))" }
Write-Host "  IP address(es) : $($ips -join ', ')"
Write-Host "  SSH port       : 22"
Write-Host "  Username       : $AuditUser"
$keygen = Join-Path $env:WINDIR "System32\OpenSSH\ssh-keygen.exe"
foreach ($name in "ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub", "ssh_host_rsa_key.pub") {
    $key = Join-Path $env:ProgramData "ssh\$name"
    if (Test-Path $key) { Write-Host "  Host key       : $(& $keygen -lf $key)" }
}
Write-Host "Compare the host key above with the fingerprint Bastion shows before trusting it."
Write-Host "To undo after the demo: powershell -ExecutionPolicy Bypass -File windows_lab_setup.ps1 -Remove"
