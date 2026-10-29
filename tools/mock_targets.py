"""Lightweight Local Mock SSH Network Target for BaselineGuard.

Allows demonstrating live network collection without requiring physical hardware
or external virtual machines. Runs a pure-Python SSH server on 127.0.0.1:2222
accepting credentials:
    Username: audituser
    Password: auditpass

Supports both:
  - Interactive terminal logins (`ssh -p 2222 audituser@127.0.0.1`)
  - Automated collection (Paramiko / Netmiko `exec_command`)
"""

from __future__ import annotations

import argparse
import io
import logging
from pathlib import Path
import socket
import sys
import threading
import time

import paramiko

# Suppress internal paramiko transport banner negotiation noise
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
HOST_KEY_FILE = DATA_DIR / "mock_ssh_host_rsa.key"

MOCK_RESPONSES = {
    "/usr/bin/uname -srm": "Linux 5.15.0-105-generic x86_64\n",
    "/usr/bin/cat /etc/os-release": (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\n'
        'ID_LIKE=debian\n'
        'VERSION_ID="22.04"\n'
    ),
    "/usr/sbin/sshd -T": (
        "permitrootlogin no\n"
        "passwordauthentication no\n"
        "x11forwarding no\n"
        "maxauthtries 4\n"
        "clientaliveinterval 300\n"
        "clientalivecountmax 3\n"
    ),
    "/usr/sbin/sysctl -n kernel.randomize_va_space fs.suid_dumpable net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies": (
        "2\n0\n0\n0\n0\n0\n0\n1\n"
    ),
    "/usr/bin/stat -c '%n %a' /etc/passwd /etc/shadow /etc/ssh/sshd_config /var/log/auth.log": (
        "/etc/passwd 0644\n"
        "/etc/shadow 0640\n"
        "/etc/ssh/sshd_config 0600\n"
        "/var/log/auth.log 0640\n"
    ),
    "/bin/grep -E '^UMASK' /etc/login.defs": "UMASK 027\n",
    "/usr/bin/systemctl is-active auditd": "active\n",
    "/usr/bin/timedatectl show -p NTPSynchronized": "NTPSynchronized=yes\n",
    "show version": (
        "Cisco IOS XE Software, Version 17.12.01\n"
        "Cisco Catalyst 9300 Series Switches\n"
        "Switch Ports Model                     SW Version            Mode\n"
        "------ ----- -----                     ----------            ----\n"
        "*    1 28    C9300-24T                 17.12.01              INSTALL\n"
    ),
    "show running-config": (
        "version 17.12\n"
        "service password-encryption\n"
        "no ip source-route\n"
        "no cdp run\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "ip http secure-server\n"
        "logging host 10.20.100.5\n"
        "ntp server 10.20.100.1\n"
        "banner motd ^Authorized Access Only^\n"
        "line vty 0 4\n"
        " exec-timeout 10 0\n"
        " transport input ssh\n"
        "!\n"
    ),
    "show interfaces switchport": (
        "Name: Gi1/0/1\n"
        "Switchport: Enabled\n"
        "Administrative Mode: static access\n"
        "Operational Mode: static access\n"
        "Access Mode VLAN: 10\n"
        "!\n"
        "Name: Gi1/0/24\n"
        "Switchport: Enabled\n"
        "Administrative Mode: trunk\n"
        "Operational Mode: trunk\n"
    ),
    "show spanning-tree summary": (
        "Switch is in rapid-pvst mode\n"
        "Root bridge for: none\n"
        "PortFast BPDU Guard is enabled\n"
    ),
    "show port-security": (
        "Port Security : Enabled\n"
        "Max Secure Addr: 1\n"
    ),
    "show vlan brief": (
        "VLAN Name                             Status    Ports\n"
        "---- -------------------------------- --------- -------------------------------\n"
        "1    default                          active    Gi1/0/2, Gi1/0/3\n"
        "10   CORPORATE                        active    Gi1/0/1\n"
    ),
}


def get_or_create_host_key() -> paramiko.RSAKey:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if HOST_KEY_FILE.exists():
        try:
            return paramiko.RSAKey(filename=str(HOST_KEY_FILE))
        except Exception:
            pass
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_FILE))
    return key


class MockServer(paramiko.ServerInterface):
    def __init__(self):
        self.shell_requested = threading.Event()
        self.exec_requested = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "audituser" and password == "auditpass":
            print(f"  [Mock SSH] Password auth SUCCESS for '{username}'", flush=True)
            return paramiko.AUTH_SUCCESSFUL
        print(f"  [Mock SSH] Password auth FAILED for '{username}'", flush=True)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if username == "audituser":
            print(f"  [Mock SSH] Publickey auth SUCCESS for '{username}'", flush=True)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.shell_requested.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        self.exec_requested.set()
        cmd_str = command.decode("utf-8", errors="replace").strip()
        print(f"  [Mock SSH] Executed command: {cmd_str}", flush=True)

        resp = MOCK_RESPONSES.get(cmd_str)
        if resp is None:
            first_word = cmd_str.split()[0] if cmd_str.split() else ""
            for k, v in MOCK_RESPONSES.items():
                if first_word and first_word in k:
                    resp = v
                    break
        if resp is None:
            resp = f"Command recognized by mock target: {cmd_str}\n"

        def _send():
            time.sleep(0.02)
            try:
                channel.sendall(resp.encode("utf-8"))
                channel.send_exit_status(0)
            except Exception:
                pass
            finally:
                time.sleep(0.02)
                try:
                    channel.close()
                except Exception:
                    pass

        threading.Thread(target=_send, daemon=True).start()
        return True


def handle_shell(channel) -> None:
    try:
        channel.sendall(b"\r\n--- BaselineGuard Mock Target SSH Shell ---\r\nswitch# ")
        buf = ""
        while not channel.closed:
            data = channel.recv(1024)
            if not data:
                break
            text = data.decode("utf-8", errors="replace")
            # Echo input back to client terminal
            channel.sendall(data)
            for ch in text:
                if ch in ("\r", "\n"):
                    line = buf.strip()
                    buf = ""
                    if line in ("exit", "quit"):
                        channel.sendall(b"\r\nConnection closed by foreign host.\r\n")
                        channel.close()
                        return
                    elif line:
                        res = MOCK_RESPONSES.get(line)
                        if not res:
                            for k, v in MOCK_RESPONSES.items():
                                if line.lower() in k.lower() or k.lower() in line.lower():
                                    res = v
                                    break
                        if res:
                            channel.sendall(b"\r\n" + res.replace("\n", "\r\n").encode("utf-8"))
                        else:
                            channel.sendall(b"\r\n% Unrecognized command in mock simulator.\r\n")
                    channel.sendall(b"\r\nswitch# ")
                elif ch in ("\b", "\x7f"):
                    buf = buf[:-1] if buf else ""
                else:
                    buf += ch
    except Exception:
        pass
    finally:
        try:
            channel.close()
        except Exception:
            pass


def handle_connection(client: socket.socket, addr: tuple[str, int], server_key: paramiko.RSAKey) -> None:
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(server_key)
        server = MockServer()
        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError, TimeoutError, socket.error):
            return

        while transport.is_active():
            chan = transport.accept(1)
            if chan is not None:
                # Wait for client to indicate exec or shell request
                for _ in range(50):
                    if server.shell_requested.is_set() or server.exec_requested.is_set():
                        break
                    time.sleep(0.05)

                if server.shell_requested.is_set():
                    handle_shell(chan)
                    break
    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass


def run_mock_server(port: int = 2222, host: str = "127.0.0.1") -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    server_key = get_or_create_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(25)

    print("\n" + "=" * 65)
    print(f"  [+] BaselineGuard Mock Target SSH Server listening on {host}:{port}")
    print("  [+] Username: audituser  |  Password: auditpass")
    print("  [+] Simulates: Ubuntu 22.04 LTS & Cisco IOS XE switch/router")
    print("  [!] Connect via: ssh -p 2222 audituser@127.0.0.1")
    print("=" * 65 + "\n", flush=True)

    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(client, addr, server_key), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("\nShutting down Mock SSH daemon.")
            break
        except Exception as e:
            print(f"[Mock SSH] Listener error: {e}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    run_mock_server(port=args.port, host=args.host)
