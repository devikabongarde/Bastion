# Runbook: onboard real Ubuntu machines on a lab network

Use this runbook to audit physical or virtual Ubuntu machines on a lab LAN with the `linux-ssh` adapter. Bastion runs only the fixed read-only commands listed in [adapters](../adapters/compatibility.md#linux-linux-ssh-exact-commands). Do this only on machines you are authorized to audit.

**Example values used below:** lab subnet `192.168.1.0/24`, target `192.168.1.50`, audit account `audituser`. Replace them with your own.

## Before you start

- Bastion (API with `BG_EMBEDDED_WORKERS=true`, plus the web console) runs on a laptop or PC that is **on the same lab network**. See [demo-day startup](demo-day.md#startup-sequence).
- You are signed in as a user with **platform_admin** (to create the site and connect) and **scan_operator** (to scan). In the demo org, `ava` has both.
- `BG_LAB_TARGETS` is **not** needed for real LAN addresses. It only allows loopback.
- Private RFC 1918 addresses are fine. Carrier-grade NAT addresses (`100.64.0.0/10`, used by some VPN overlays) are refused as `TARGET_ADDRESS_PROHIBITED`. Use the machine's LAN address.

## Step 1: Verify the network from the Bastion laptop

```powershell
ping 192.168.1.50
Test-NetConnection 192.168.1.50 -Port 22      # TcpTestSucceeded : True (after step 2 if SSH is not installed yet)
ipconfig                                       # note the laptop's own subnet
```

If ping fails but the machines are on the same switch, check the guest/client isolation setting on the Wi-Fi, and the host firewall.

## Step 2: Run the setup script on each Ubuntu machine

Copy `tools/ubuntu_lab_setup.sh` to the machine (USB, `scp`, or paste it), then run:

```bash
sudo bash ubuntu_lab_setup.sh            # optional argument: audit username (default audituser)
```

The script is safe to re-run. It:

1. Installs and enables `openssh-server` and `auditd`. The Linux policy checks that auditd is active. auditd may fail to start in containers or WSL; the scan then reports it as inactive.
2. Creates `audituser` with no admin rights and prompts you to set its password.
3. Writes `/etc/sudoers.d/bastion-audit` (validated with `visudo -c`):
   ```
   audituser ALL=(root) NOPASSWD: /usr/sbin/sshd -T
   ```
   This allows that **one** read-only command and nothing else. The reader tries `sshd -T` unprivileged first, then falls back to `sudo -n /usr/sbin/sshd -T`.
4. Warns you if SSH password login is disabled, and prints the one-line `Match User` override. The Bastion Connect dialog only accepts a password; see [troubleshooting](#troubleshooting).
5. Prints the machine's IP addresses, port 22, the username and the **host-key fingerprints**. Keep these for step 6.

To print the fingerprint yourself at any time:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

## Step 3: Create a site for the lab subnet

In the console, go to **Assets → New site** (platform_admin only):

| Field | Example | Notes |
|---|---|---|
| Name | `Ubuntu Lab` | Unique within the org |
| Timezone | pre-filled from the browser | Must be an IANA name |
| Allowed networks (CIDR) | `192.168.1.0/24` | Use the narrowest range that covers the machines. `/0` is rejected. |
| Allowed ports | `22` | Comma-separated |
| DNS suffixes | *(empty)* | Only needed if you register machines by host name |

The equivalent API call is `POST /api/v1/sites` with an `Idempotency-Key`. Bastion will refuse to connect to anything outside this scope.

## Step 4: Preflight from the Bastion laptop

```powershell
.\.venv\Scripts\python.exe tools/check_ubuntu_target.py 192.168.1.50 --user audituser
```

The script runs four steps:

1. **TCP** reachability on port 22.
2. **Host key.** It prints the type and the `SHA256:` fingerprint and asks you to confirm before it sends any password. Pass `--fingerprint SHA256:...` to compare non-interactively.
3. **Login** with a prompted password (or `BASTION_SSH_PASSWORD`, or `--key <file>`).
4. **Each read-only command.** It reports OK or a failure with a hint, then shows the detected platform and how many policy facts are verifiable.

Other options: `--port`, `--timeout`. It stores nothing and changes nothing on the target. Fix anything it flags before continuing. The usual case is the `linux.ssh.effective_config` reader failing because the sudoers rule is missing.

## Step 5: Add the asset

Go to **Assets → Add asset**:

| Field | Value |
|---|---|
| Site | `Ubuntu Lab` |
| Name | e.g. `lab-ubuntu-50` |
| Address / Port | `192.168.1.50` / `22` |
| Category | Linux server |
| Collection | **Linux · live SSH** (`linux-ssh`) |
| Role | `server` (default) |

If the address or port is outside the site, the API returns `ASSET_OUTSIDE_SITE_SCOPE`. The new asset shows **Connect** instead of **Scan** until its key is pinned and a credential is bound.

## Step 6: Connect, compare the fingerprint, trust

1. Click **Connect** on the asset. Bastion reads the host key (`POST /assets/{id}/host-key`) and shows the key type and `SHA256:` fingerprint.
2. On the Ubuntu machine, run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Compare the fingerprint with the one in Bastion **character by character**. If Bastion shows an RSA or ECDSA key, compare with that `.pub` file instead.
3. Enter `audituser` and its password, then click **Trust this key & connect**.

Bastion re-reads the key. If it changed since step 1, nothing is saved (`HOST_KEY_CHANGED`). Otherwise Bastion:

- pins the key in `BG_KNOWN_HOSTS_FILE`;
- records the trust;
- encrypts and binds the credential.

The asset now shows the pinned fingerprint and a **Scan** button.

## Step 7: Scan

Click **Scan** on the asset, **Scan all live (N)**, or **Scan now** in the detail sheet. The console polls until the run is `COMPLETED` or `PARTIAL`, then refreshes Overview, Findings and Assessments.

- Ubuntu controls show PASS or FAIL. A stock Ubuntu install reports `permitrootlogin without-password`, which is normalized to `prohibit-password`. The root-login control expects `no`, so it is a real FAIL. Controls whose facts could not be read show `UNKNOWN`. Controls for Windows, Cisco and FortiGate show `NOT_APPLICABLE`.
- A run is `PARTIAL` whenever any control is `UNKNOWN` or `ERROR`.

### Optional: live flip demo (PermitRootLogin)

On the Ubuntu machine:

```bash
echo 'PermitRootLogin no' | sudo tee /etc/ssh/sshd_config.d/99-flip.conf && sudo systemctl reload ssh
sudo sshd -T | grep permitrootlogin      # expect: permitrootlogin no
```

Scan the asset in Bastion. The root-login control is now **PASS**. Change the file to `PermitRootLogin yes`, reload ssh, check with `sudo sshd -T | grep permitrootlogin`, and scan again. The control is now **FAIL**, and the finding reopens. Remove the file afterwards (`sudo rm /etc/ssh/sshd_config.d/99-flip.conf && sudo systemctl reload ssh`).

Files in `sshd_config.d` are read in lexical order, and the first value wins. If an earlier file already sets `PermitRootLogin`, edit that file instead. Always confirm the effective value with `sshd -T` before scanning.

## Troubleshooting

Connect-time errors appear in the Connect sheet; their codes come from the API. Collection errors make the affected controls `ERROR` ("collection failed"). The UI does not show the raw collection code. To see it, query the database (superuser):

```powershell
docker compose -f deploy/compose/compose.yaml exec postgres psql -U postgres -d baselineguard -c "select kind, state, attempt, error_code, available_at from jobs order by available_at desc limit 10;"
```

| Code | Where | Cause | Fix |
|---|---|---|---|
| `ASSET_OUTSIDE_SITE_SCOPE` | Add asset | Address not in the site's CIDRs or DNS suffixes, or port not allowed | Fix the address or port, or create a site that covers it |
| `TARGET_ADDRESS_OUT_OF_SCOPE` | Connect / scan | The resolved address is outside `allowed_cidrs` | Widen the site CIDR to include the machine |
| `TARGET_PORT_OUT_OF_SCOPE` | Connect / scan | Asset port not in `allowed_ports` | Add the port to the site, or correct the asset |
| `TARGET_NAME_OUT_OF_SCOPE` / `TARGET_NAME_RESOLUTION_FAILED` | Connect / scan | Host name not under an allowed suffix, or not resolvable | Use the IP address, or add the suffix and fix DNS |
| `TARGET_ADDRESS_PROHIBITED` | Connect / scan | Loopback, link-local, multicast, reserved or CGNAT (`100.64/10`) address | Use the LAN IP. Loopback works only with `BG_LAB_TARGETS=true`. |
| `TARGET_UNREACHABLE` (HTTP 502) | Connect | No SSH handshake within 8 s | Check `Test-NetConnection -Port 22`, `systemctl status ssh` and `ufw allow 22/tcp` |
| `HOST_KEY_CHANGED` (HTTP 409) | Connect | The key differs between reading and trusting | Stop and investigate. Do not trust a changing key. |
| `SSH_AUTHENTICATION_FAILED` | Scan | Wrong password, or password login disabled for the account | Re-run Connect with the right password. If `sshd -T` shows `passwordauthentication no`, add `Match User audituser` / `PasswordAuthentication yes` in `/etc/ssh/sshd_config.d/90-bastion.conf` and `systemctl reload ssh` (the setup script prints this), or bind a key via the API (`private_key_pem`). |
| `SSH_HOST_KEY_MISMATCH` | Scan | The machine presents a different key than the pinned one (reinstall, regenerated keys, or a different host on that IP) | Verify on the console, then **Re-pin host key & credential** from the asset sheet |
| `TRUST_NOT_VERIFIED` | Scan | Collection succeeded, but the asset has no active trust record (for example, the key was pinned outside the Connect flow) | Run Connect for this asset |
| `SSH_COLLECTION_FAILED` | Scan | Connection or SSH error, **or the key is not in known_hosts** (unknown keys are rejected) | Check reachability. Make sure the API and collector use the same `BG_KNOWN_HOSTS_FILE`. Re-run Connect. |
| `CREDENTIAL_NOT_BOUND` | Scan | The asset was never connected | Run Connect |
| Scan runs for about a minute, then every control is `ERROR` | Scan | A retryable error (`SSH_COLLECTION_FAILED`, `READER_TIMEOUT`, …) persisted through 3 attempts (20 s and 40 s backoff) | Read `jobs.error_code` with the query above, fix the cause, scan again |
| SSH controls `UNKNOWN` | Results | `sshd -T` failed and `sudo -n` was refused | Re-run the setup script, or check `sudo -l -U audituser` lists `/usr/sbin/sshd -T` |
| auditd control FAIL / `UNKNOWN` | Results | auditd not installed or not running | A real finding. Install or start auditd if the lab requires it. |
| File-mode control `UNKNOWN` | Results | `/var/log/auth.log` missing (journald-only systems) | Expected on such hosts |

## Removing a machine

Archive the asset from its detail sheet. On the machine:

```bash
sudo rm /etc/sudoers.d/bastion-audit
sudo deluser --remove-home audituser
```

The pinned key stays in `BG_KNOWN_HOSTS_FILE` until you edit that file.
