#!/usr/bin/env bash
# Prepare an Ubuntu machine to be audited by Bastion over SSH.
#
#   sudo bash ubuntu_lab_setup.sh [audit-username]
#
# Installs and starts OpenSSH (and auditd, which the policy checks), creates a dedicated
# audit account, and grants it passwordless sudo for exactly one read-only command:
# `/usr/sbin/sshd -T` (print effective SSH config; it needs root to read host keys).
# Every other Bastion check runs unprivileged. Safe to re-run.
set -euo pipefail

AUDIT_USER="${1:-audituser}"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0 [audit-username]" >&2
  exit 1
fi
if ! grep -q '^ID=ubuntu' /etc/os-release; then
  echo "Warning: this is not Ubuntu; the Bastion Linux policy targets Ubuntu." >&2
fi

echo "[1/4] Installing openssh-server and auditd"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server auditd >/dev/null
systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd
systemctl enable --now auditd >/dev/null 2>&1 || echo "  auditd could not start (expected in containers/WSL); the scan will report it inactive."

echo "[2/4] Creating audit account '$AUDIT_USER'"
if id "$AUDIT_USER" >/dev/null 2>&1; then
  echo "  account exists, leaving its password unchanged"
else
  adduser --disabled-password --gecos "Bastion audit (read-only)" "$AUDIT_USER" >/dev/null
  echo "  set a password for $AUDIT_USER (you will enter it in Bastion when connecting):"
  passwd "$AUDIT_USER"
fi

echo "[3/4] Allowing '$AUDIT_USER' to run only: /usr/sbin/sshd -T"
SUDOERS=/etc/sudoers.d/bastion-audit
printf '%s ALL=(root) NOPASSWD: /usr/sbin/sshd -T\n' "$AUDIT_USER" > "$SUDOERS.tmp"
chmod 0440 "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp" >/dev/null
mv "$SUDOERS.tmp" "$SUDOERS"

if sshd -T 2>/dev/null | grep -qx 'passwordauthentication no'; then
  echo "  Note: SSH password login is disabled on this machine. Either connect from Bastion"
  echo "  with an SSH private key for $AUDIT_USER, or enable passwords for this account only:"
  echo "    printf 'Match User $AUDIT_USER\\n  PasswordAuthentication yes\\n' > /etc/ssh/sshd_config.d/90-bastion.conf && systemctl reload ssh"
fi

echo "[4/4] Details to enter in Bastion"
echo "  IP address(es) : $(hostname -I)"
echo "  SSH port       : 22"
echo "  Username       : $AUDIT_USER"
for key in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
  [[ -f $key ]] && echo "  Host key       : $(ssh-keygen -lf "$key")"
done
echo "Compare the host key above with the fingerprint Bastion shows before trusting it."
