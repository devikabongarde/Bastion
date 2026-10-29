"""Lightweight Local Mock SSH Network Target for BaselineGuard.

Allows demonstrating live network collection without requiring physical hardware
or external virtual machines. Runs a pure-Python SSH server on 127.0.0.1:2222
accepting credentials:
    Username: audituser
    Password: auditpass
"""

from __future__ import annotations

import argparse
import socket
import threading

import paramiko

MOCK_LINUX_RESPONSES = {
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
        "Operational Mode: static access\n"
        "Access Mode VLAN: 10\n"
        "!\n"
        "Name: Gi1/0/24\n"
        "Operational Mode: trunk\n"
    ),
    "show spanning-tree summary": (
        "Switch is in rapid-pvst mode\n"
        "PortFast BPDU Guard is enabled\n"
    ),
    "show port-security": (
        "Port Security : Enabled\n"
    ),
}


class MockServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "audituser" and password == "auditpass":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        cmd_str = command.decode("utf-8", errors="replace").strip()
        print(f"  [Mock SSH] Received command: {cmd_str}")

        # Find matching response
        response = MOCK_LINUX_RESPONSES.get(cmd_str)
        if response is None:
            # Substring match
            for k, v in MOCK_LINUX_RESPONSES.items():
                if k.split()[0] in cmd_str:
                    response = v
                    break
        if response is None:
            response = "Command recognized by mock target.\n"

        channel.send(response.encode("utf-8"))
        channel.send_exit_status(0)
        channel.close()
        return True


def run_mock_server(port: int = 2222, host: str = "127.0.0.1") -> None:
    key = paramiko.RSAKey.generate(2048)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(10)
    print("\n=======================================================")
    print(f"  Mock Target SSH Daemon listening on {host}:{port}")
    print("  Accepting credentials -> Username: audituser | Password: auditpass")
    print("  Simulates: Ubuntu 22.04 LTS & Cisco IOS XE switch/router")
    print("=======================================================\n")

    while True:
        try:
            client, addr = sock.accept()
            print(f"[Mock SSH] Inbound audit connection from {addr[0]}:{addr[1]}")
            transport = paramiko.Transport(client)
            transport.add_server_key(key)
            server = MockServer()
            transport.start_server(server=server)
        except Exception as e:
            print(f"[Mock SSH] Connection error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    run_mock_server(port=args.port, host=args.host)
