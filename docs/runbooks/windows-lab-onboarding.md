# Onboarding a remote Windows PC (`windows-ssh`)

Audit another Windows 10/11 PC over the network, the same way as an Ubuntu machine. The target runs the
**built-in Windows OpenSSH Server**. Bastion connects over SSH with a pinned host key and runs exactly the
same fixed, read-only commands as the local Windows audit (`WINDOWS_READERS` in
`packages/adapters/src/baselineguard_adapters/windows/reader.py`), so the same Windows rule pack applies.

| Where | Who |
|---|---|
| **Target PC** (e.g. a friend's laptop) | Needs local admin once, to run the setup script |
| **Bastion host** (your laptop) | Runs the preflight check and the web console |

## 1. Network check (Bastion host)

Both machines must be on the same network. Campus Wi-Fi often blocks device-to-device traffic. If it does, put
both on one phone hotspot.

```powershell
Test-NetConnection <target-ip> -Port 22     # after step 2; needs TcpTestSucceeded : True
```

Find the target's IP on the target with `ipconfig` (IPv4 Address of the Wi-Fi adapter).

## 2. Set up the target PC (once)

Copy `tools/windows_lab_setup.ps1` to the target (USB, chat or e-mail), then in **PowerShell opened with
"Run as administrator"**:

```powershell
powershell -ExecutionPolicy Bypass -File .\windows_lab_setup.ps1
```

It:
1. installs and starts the Windows **OpenSSH Server** capability (the first install can take a few minutes);
2. opens inbound TCP 22 in Windows Firewall (rule `Bastion-SSH-In`);
3. creates a local account `bastionaudit` (asks you to choose its password) in **Administrators**. `secedit`
   and `auditpol` only report password, lockout and audit policy to an elevated token, which Windows OpenSSH
   gives administrators;
4. prints the IP addresses, the username and the SSH **host key fingerprint**.

**Undo after the demo:** `powershell -ExecutionPolicy Bypass -File .\windows_lab_setup.ps1 -Remove` deletes the
account and the firewall rule and stops and disables `sshd`.

## 3. Preflight (Bastion host)

```powershell
.\.venv\Scripts\python.exe tools\check_ubuntu_target.py <target-ip> --user bastionaudit --platform windows
```

Confirm the fingerprint matches what the setup script printed, then enter the `bastionaudit` password. All
six readers should show `ok`. If `secedit`/`auditpol` fail with `Error 0x00000522`, the account is not an
administrator.

## 4. Add it in Bastion (web console, as a platform admin)

1. **Assets → New site**: allowed networks `<target-ip>/32`, allowed ports `22`.
2. **Assets → Add asset**: that site, the target's IP, port `22`, category **Windows**, collection
   **Windows · live SSH (OpenSSH Server)**.
3. Open the asset → **Connect** → compare the fingerprint → username `bastionaudit` + password → **Trust
   this key & connect**. The host key column shows **Pinned**.
4. **Scan**, then open the run on **Assessments** to see every Windows control, expected vs. observed.

## Notes

- Per-user checks (screen saver) read `HKCU` of the **`bastionaudit`** profile, because that is the account
  Bastion signs in as.
- Laptops on DHCP may get a new IP after reconnecting. Re-check with `ipconfig` and re-add the site/asset if it
  changed; the host key stays the same.
- Errors and fixes are the same as for Ubuntu: see the troubleshooting table in
  [ubuntu-lab-onboarding.md](ubuntu-lab-onboarding.md).
