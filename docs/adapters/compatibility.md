# Adapters and compatibility

Adapters live in `packages/adapters/src/baselineguard_adapters/`. Every reader runs a **fixed command table** defined in code. No route or field accepts command text from callers. The asset's `adapter_id` selects the collection path (see `collection_mode()` in `routes/v1/inventory.py` and `CollectorWorker._collect`).

| `adapter_id` | Mode | Transport | Target | Rule pack used (by `platform.family`) |
|---|---|---|---|---|
| `linux-ssh` | `live_ssh` | SSH exec (paramiko) | Ubuntu (pack family `ubuntu`) | `org.baselineguard.linux.phase1` |
| `cisco-iosxe` | `live_ssh` | SSH interactive shell | Cisco IOS XE router or switch (`declared_role` router/switch; anything else is treated as switch) | `org.baselineguard.cisco.iosxe` |
| `fortigate-ssh` | `live_ssh` | SSH exec | FortiGate (FortiOS CLI) | `org.baselineguard.fortinet.fortigate` |
| `windows-local` | `live_local` | Local `subprocess` on the **collector host** | The Windows machine running the API/collector (`windows` / `windows_server`) | `org.baselineguard.windows.server2019` |
| `windows-ssh` | `live_ssh` | SSH exec to the built-in **Windows OpenSSH Server** (pinned host key, sealed credential) | A remote Windows 10/11 PC; the account must be a local Administrator | `org.baselineguard.windows.server2019` |
| `linux-ssh-fixture`, `cisco-iosxe-fixture`, `fortigate-fixture`, `windows-fixture` | `fixture` | Reads raw-output fixture files (needs a `fixture_root`, which the embedded worker does not configure) | Demo / sample assets | as above |
| any other id | `import` | None; evidence comes via `POST /api/v1/imports` | Offline evidence | as above |

**Applicability.** A pack's `targets.version_range` (for example Ubuntu `>=20.04 <23.0`) is **metadata only**. No code reads it. Each control decides whether it applies through its `applicability` expression, normally `platform.family == <family>`; Windows uses `platform.family in [windows_server, windows]`. Some Cisco controls also check `platform.role`. On another platform a control evaluates to `NOT_APPLICABLE`. When collection fails, the evaluator falls back to the asset's declared `identity.family` and `identity.role`, so only that asset's own controls become `ERROR`.

## Linux (`linux-ssh`): exact commands

From `LINUX_READERS` in `linux/ssh.py`. They run over SSH `exec` without a PTY, with a 10 s timeout per command and output capped at 1 MiB.

| Reader id | Command | Facts produced |
|---|---|---|
| `linux.identity.uname` | `/usr/bin/uname -srm` | (collected; not normalized) |
| `linux.identity.os_release` | `/usr/bin/cat /etc/os-release` | `platform.family`, `platform.version` |
| `linux.ssh.effective_config` | `/usr/sbin/sshd -T 2>/dev/null \|\| /usr/bin/sudo -n /usr/sbin/sshd -T` | `auth.ssh.*` (PermitRootLogin, PasswordAuthentication, X11Forwarding, MaxAuthTries, ClientAliveInterval/CountMax) |
| `linux.kernel.security_sysctl` | `/usr/sbin/sysctl -n kernel.randomize_va_space fs.suid_dumpable net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies` | Kernel sysctls. Values are trusted only if the command exits 0, because the output is positional. |
| `linux.files.security_modes` | `/usr/bin/stat -c '%n %a' /etc/passwd /etc/shadow /etc/ssh/sshd_config /var/log/auth.log` | File permission modes |
| `linux.auth.umask_defaults` | `/bin/grep -E '^UMASK' /etc/login.defs` | Default umask |
| `linux.auditd.active` | `/usr/bin/systemctl is-active auditd` | `services.auditd.active` |
| `linux.time.ntp_state` | `/usr/bin/timedatectl show -p NTPSynchronized` | NTP synchronization |

`sshd -T` must read the host private keys, so it fails for an unprivileged account. The command then falls back to `sudo -n`, which works only if a sudoers rule allows exactly `/usr/sbin/sshd -T` without a password. `tools/ubuntu_lab_setup.sh` installs that rule; see [Ubuntu lab onboarding](../runbooks/ubuntu-lab-onboarding.md).

A command that exits non-zero or writes to stderr does not abort collection. The reader keeps each command's stdout and exit code. Facts it cannot read become unavailable, so the related controls evaluate to `UNKNOWN`. The normalizer maps `sshd -T`'s legacy `permitrootlogin without-password` to `prohibit-password` (PRESENT). The root-login control expects `no`, so a stock Ubuntu host gives a real FAIL rather than UNKNOWN.

## Cisco IOS XE (`cisco-iosxe`)

From `cisco_iosxe/reader.py`. The reader opens an interactive shell and sends the session-local display commands `terminal length 0` and `terminal width 511`, which do not change the configuration. It then runs:

| Always | Router role | Switch role |
|---|---|---|
| `show version`, `show running-config`, `show clock` | `show ip interface brief` | `show interfaces switchport`, `show spanning-tree summary`, `show port-security`, `show vlan brief`, `show interfaces status` |

Lines containing secret keywords (`password`, `secret`, `community`, `user`, `authentication-key`, `privacy-key`, `key-string`, `pre-shared-key`) are redacted before storage. The command prefix is kept so that presence can still be audited. The reader detects pagination prompts (`OUTPUT_PAGINATION_DETECTED`) and device-rejected commands (`DEVICE_REJECTED_READ_COMMAND`). The device role (`platform.role`) is inferred from which reader set ran.

## FortiGate (`fortigate-ssh`)

From `fortigate/reader.py`: `get system status`, `get system global`, `get system admin settings`, `show firewall policy`, `get system interface`, `get log syslogd setting`, `show system ntp`, `show system snmp community`, `show system snmp user`, `show system password-policy`.

## Windows (`windows-local`)

From `windows/reader.py`. The reader runs on the collector host with `shell=True`, a 10 s timeout from the worker, and a 1 MiB cap.

| Reader id | Command (summary) |
|---|---|
| `windows.identity.os_version` | `Get-CimInstance Win32_OperatingSystem` → JSON |
| `windows.registry.security_settings` | `Get-ItemProperty` for LimitBlankPasswordUse, SMB1, UAC (EnableAdminApprovalMode, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop), UserRemoteLogonRestriction, RDP fPromptForPassword / UserAuthentication, screen-saver settings |
| `windows.security_policy.secedit` | `secedit /export` to a temp file, which is printed and then deleted |
| `windows.audit.auditpol` | `auditpol.exe /get /category:* /r` |
| `windows.firewall.profiles` | `Get-NetFirewallProfile` → JSON |
| `windows.services.state` | `Get-Service` Telnet, RemoteRegistry, SSDPSRV, upnphost, XboxGipSvc → JSON |

`secedit` and `auditpol` reveal password/lockout and audit-policy settings only to an elevated process. Without elevation those controls show `UNKNOWN`. Remote Windows PCs are audited with `windows-ssh` (below), not WinRM. A `windows-local` asset always audits the machine the collector runs on, whatever address is stored on the asset. The same commands are available as a terminal tool: `tools/audit_local_machine.py`.

## Remote Windows (`windows-ssh`)

From `windows/ssh.py`. `WindowsSSHReader` subclasses the SSH reader and runs the **same `WINDOWS_READERS` commands** as `windows-local`, over SSH to Windows OpenSSH Server (whose default shell is `cmd.exe`). Onboarding, scope checks, host-key pinning, retries and normalization are identical to `linux-ssh`. Each reader gets a 30 s timeout (PowerShell start-up). Output is decoded as UTF-8, falling back to the OEM code page (cp437). The account must be a local Administrator for `secedit`/`auditpol`. `HKCU` checks reflect the audit account's own profile. Setup: `tools/windows_lab_setup.ps1`; runbook: [windows-lab-onboarding.md](../runbooks/windows-lab-onboarding.md).

## Site scope allow-lists

`resolve_authorized_endpoint()` in `base/transport.py` runs:

- in the collector, before every live SSH collection;
- in the API, before reading a host key.

It applies these checks in order:

1. The port must be in the site's `allowed_ports`. Otherwise: `TARGET_PORT_OUT_OF_SCOPE`.
2. If the address is a hostname, it must equal or end with one of `allowed_dns_suffixes`. Otherwise: `TARGET_NAME_OUT_OF_SCOPE`. The name is then resolved once; if resolution fails: `TARGET_NAME_RESOLUTION_FAILED`.
3. If any resolved address is unspecified, loopback, link-local, multicast, reserved, or neither private nor global, the target is refused with `TARGET_ADDRESS_PROHIBITED`. The "neither private nor global" case includes carrier-grade NAT `100.64.0.0/10`, which is used by some VPN overlays.
4. Every resolved address must lie inside one of `allowed_cidrs`. Otherwise: `TARGET_ADDRESS_OUT_OF_SCOPE`.
5. The socket connects to the first authorized IP (pinned) while SSH still uses the original host name for its known_hosts lookup.

**`BG_LAB_TARGETS` loopback rule.** Loopback addresses are refused unless `BG_LAB_TARGETS=true` **and** `BG_ENVIRONMENT` is not `production` (the settings validator rejects `BG_LAB_TARGETS` in production). Even then, a loopback target must still be inside the site's `allowed_cidrs` (e.g. `127.0.0.0/8`) and `allowed_ports` (e.g. `2222`). `tools/sync_demo.py` creates exactly that site, "Security Lab".

Registering an asset (`POST /api/v1/assets`) applies a lighter check: IP-in-CIDR or name-under-suffix, plus port. It does not check for prohibited address classes. The full check happens at connect and collect time.

## Host-key pinning flow

Implemented in `apps/api/src/baselineguard_api/routes/v1/live.py` and enforced by `base/transport.make_strict_ssh_client`.

```mermaid
sequenceDiagram
  participant Admin as Admin (Assets → Connect)
  participant API
  participant Dev as Device
  Admin->>API: POST /assets/{id}/host-key
  API->>Dev: scope check + SSH handshake (no auth)
  API-->>Admin: {key_type, fingerprint: SHA256:...}
  Admin->>Admin: compare with device console
  Admin->>API: POST /assets/{id}/connect {username, password, fingerprint}
  API->>Dev: re-read key; mismatch → 409 HOST_KEY_CHANGED
  API->>API: pin in BG_KNOWN_HOSTS_FILE ("host" or "[host]:port")
  API->>API: revoke old asset_trust, insert new; seal + bind credential
```

What the collector enforces:

- It uses paramiko `RejectPolicy` with only `BG_KNOWN_HOSTS_FILE` loaded.
- An **unknown** key fails the connection, reported as `SSH_COLLECTION_FAILED`.
- A **different** key gives `SSH_HOST_KEY_MISMATCH`.
- A missing known_hosts file is an unexpected error, reported as `COLLECTOR_UNEXPECTED`.
- After a successful live SSH collection, the asset must also have an unrevoked `asset_trust` row. Otherwise the snapshot is recorded with `TRUST_NOT_VERIFIED` and all of its controls become `ERROR`.

The web Connect sheet sends only a password. The API also accepts `private_key_pem` (Ed25519, ECDSA or RSA).

## Collection error codes

| Code | Source | Retryable? |
|---|---|---|
| `TARGET_PORT_OUT_OF_SCOPE`, `TARGET_NAME_OUT_OF_SCOPE`, `TARGET_NAME_RESOLUTION_FAILED`, `TARGET_ADDRESS_PROHIBITED`, `TARGET_ADDRESS_OUT_OF_SCOPE` | scope check | no |
| `CREDENTIAL_NOT_BOUND`, `CREDENTIAL_DECRYPT_FAILED`, `CREDENTIAL_KEY_INVALID`, `CREDENTIAL_MATERIEL_UNAVAILABLE` | credential lookup | no |
| `SSH_AUTHENTICATION_FAILED`, `SSH_HOST_KEY_MISMATCH` | readers | no |
| `SSH_COLLECTION_FAILED`, `READER_TIMEOUT`, `OUTPUT_LIMIT_EXCEEDED`, `OUTPUT_ENCODING_UNSUPPORTED` | Linux reader | yes: up to 3 attempts with 20 s / 40 s backoff, then fail closed |
| `FORTIGATE_TRANSPORT_ERROR: …`, `WINDOWS_EXEC_ERROR: …`, `READER_OUTPUT_LIMIT_EXCEEDED`, Cisco reader codes | other readers | no |
| `TRUST_NOT_VERIFIED` | collector, after collection | n/a (recorded as an ERROR outcome) |
| `UNSUPPORTED_ADAPTER`, `FIXTURE_ROOT_NOT_CONFIGURED`, `COLLECTOR_UNEXPECTED` | collector | no |

These codes are stored in `jobs.error_code` and `snapshots.completeness->>'error_code'`. The UI shows the affected controls as `ERROR` ("collection failed"), not the raw code.

## Verification status

`content/compatibility.yaml` still records every platform as `planned` with no verified build. The `linux-ssh`, `cisco-iosxe` and `fortigate-ssh` readers have been exercised against the bundled mock SSH device (`tools/mock_targets.py`, which answers the exact command strings) and in unit tests (`tests/unit/test_*_adapter.py`, `test_collector_scope.py`). `windows-local` runs against the real host. None of this is a vendor-lab certification of a specific build.
