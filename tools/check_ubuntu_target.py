"""Preflight an Ubuntu machine before adding it to Bastion as a live SSH asset.

    .\\.venv\\Scripts\\python.exe tools/check_ubuntu_target.py 192.168.1.50 --user audituser

Checks, in order: TCP reachability, the SSH host-key fingerprint (you confirm it before any
password is sent), login, and every read-only command the Linux adapter runs, then shows
which policy facts the scan will be able to verify. Nothing is stored and nothing on the
target is changed. The password is prompted for, or read from BASTION_SSH_PASSWORD.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import socket
import sys
import time

import paramiko
from baselineguard_adapters.linux.ssh import LINUX_READERS, ReadOutput
from baselineguard_adapters.orchestrate import normalize_outputs
from baselineguard_contracts.common import FactState

from baselineguard_api.routes.v1.live import fingerprint_of

HINTS = {
    "linux.ssh.effective_config": "grant the sudoers rule from tools/ubuntu_lab_setup.sh",
    "linux.auditd.active": "auditd is not running (a real finding, not a setup error)",
    "linux.files.security_modes": "a listed file is missing on this host",
}


def run(transport: paramiko.Transport, command: str, timeout: float) -> tuple[int, bytes, bytes]:
    channel = transport.open_session(timeout=timeout)
    channel.settimeout(timeout)
    channel.exec_command(command)
    out, err = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    while not (channel.exit_status_ready() and not channel.recv_ready()
               and not channel.recv_stderr_ready()):
        if channel.recv_ready():
            out.extend(channel.recv(65536))
        if channel.recv_stderr_ready():
            err.extend(channel.recv_stderr(65536))
        if time.monotonic() > deadline:
            raise TimeoutError(command)
        time.sleep(0.01)
    code = channel.recv_exit_status()
    channel.close()
    return code, bytes(out), bytes(err)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # pyright: ignore[reportAttributeAccessIssue]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", default="audituser")
    parser.add_argument("--key", help="private key file instead of a password")
    parser.add_argument("--fingerprint", help="expected SHA256:... fingerprint; skips the prompt")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()

    print(f"[1/4] TCP {args.host}:{args.port} ... ", end="", flush=True)
    try:
        sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
    except OSError as error:
        print(f"FAILED ({error})")
        print("      Is the laptop on the lab network, is openssh-server running, is port 22 open?")
        return 1
    print("ok")

    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=args.timeout)
        key = transport.get_remote_server_key()
        fingerprint = fingerprint_of(key)
        print(f"[2/4] Host key {key.get_name()} {fingerprint}")
        if args.fingerprint:
            if args.fingerprint.strip() != fingerprint:
                print("      MISMATCH with --fingerprint. Stopping before sending credentials.")
                return 1
        else:
            print("      On the target run: ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub")
            if input("      Does it match? [y/N] ").strip().lower() != "y":
                print("      Not confirmed. Stopping before sending credentials.")
                return 1

        print(f"[3/4] Login as {args.user} ... ", end="", flush=True)
        try:
            if args.key:
                transport.auth_publickey(args.user, paramiko.PKey.from_path(args.key))
            else:
                password = os.environ.get("BASTION_SSH_PASSWORD") or getpass.getpass(
                    f"password for {args.user}: "
                )
                transport.auth_password(args.user, password)
        except paramiko.AuthenticationException:
            print("FAILED: wrong credentials, or SSH password login is disabled for this account")
            return 1
        print("ok")

        print("[4/4] Read-only commands")
        results: list[tuple[str, ReadOutput]] = []
        for reader_id, command in LINUX_READERS.items():
            code, out, err = run(transport, command, args.timeout)
            status = "ok " if code == 0 else f"exit {code}"
            print(f"      {status:7} {reader_id}")
            if code != 0:
                detail = err.decode(errors="replace").strip().splitlines()[:1]
                hint = HINTS.get(reader_id, "")
                print(f"              {' '.join(detail)}  {('-> ' + hint) if hint else ''}".rstrip())
            results.append((reader_id, ReadOutput(
                reader_id=reader_id, text=out.decode(errors="replace"), exit_code=code,
                output_bytes=len(out), source_sha256=hashlib.sha256(out).hexdigest(),
            )))
    finally:
        transport.close()

    facts = normalize_outputs(results)
    present = [f for f in facts if f.state is FactState.PRESENT]
    missing = [f.fact_id for f in facts if f.state is not FactState.PRESENT]
    platform = {f.fact_id: f.value for f in present if f.fact_id.startswith("platform.")}
    print(f"\nPlatform: {platform.get('platform.family')} {platform.get('platform.version')}")
    print(f"Verifiable facts: {len(present)}/{len(facts)}")
    if missing:
        print("Cannot verify (controls using these will show as unknown):")
        for name in missing:
            print(f"  - {name}")
    print("\nReady to add in Bastion: adapter 'Linux · live SSH', this IP, port", args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
