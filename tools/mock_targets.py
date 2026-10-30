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
import logging
import socket
import sys
import threading
import time
from pathlib import Path

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
    "/usr/sbin/sshd -T 2>/dev/null || /usr/bin/sudo -n /usr/sbin/sshd -T": (
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
    # ---------------- Cisco Catalyst 9300 (IOS XE 17.12) ----------------
    "terminal length 0": "",
    "terminal width 511": "",
    "show clock": "*10:42:17.512 UTC Thu Oct 30 2026\n",
    "show version": (
        "Cisco IOS XE Software, Version 17.12.01\n"
        "Cisco Catalyst 9300 Series Switches\n"
        "core-sw-01 uptime is 41 days, 3 hours, 12 minutes\n"
        "Switch Ports Model                     SW Version            Mode\n"
        "------ ----- -----                     ----------            ----\n"
        "*    1 28    C9300-24T                 17.12.01              INSTALL\n"
    ),
    "show running-config": (
        "Building configuration...\n"
        "!\n"
        "version 17.12\n"
        "hostname core-sw-01\n"
        "service timestamps log datetime msec localtime show-timezone\n"
        "service password-encryption\n"
        "!\n"
        "enable secret 9 $9$Zc4kQ1mNbR8uLs$ExampleHashOnly\n"
        "aaa new-model\n"
        "aaa authentication login default local\n"
        "!\n"
        "no ip source-route\n"
        "ip ssh version 2\n"
        "ip ssh time-out 60\n"
        "ip ssh authentication-retries 3\n"
        "ip http server\n"
        "ip http secure-server\n"
        "ip dhcp snooping vlan 10,20\n"
        "ip dhcp snooping\n"
        "!\n"
        "logging host 10.20.100.5\n"
        "ntp server 10.20.100.1\n"
        "snmp-server community public RO\n"
        "snmp-server group MONITOR v3 priv\n"
        "spanning-tree mode rapid-pvst\n"
        "spanning-tree portfast bpduguard default\n"
        "!\n"
        "interface GigabitEthernet1/0/1\n"
        " description user-pc\n"
        " switchport access vlan 10\n"
        " switchport mode access\n"
        " switchport port-security\n"
        "!\n"
        "interface Vlan1\n"
        " ip address 10.20.1.2 255.255.255.0\n"
        "!\n"
        "interface Vlan99\n"
        " ip address 10.20.99.2 255.255.255.0\n"
        "!\n"
        "ip access-list standard MGMT-ONLY\n"
        " 10 permit 10.20.100.0 0.0.0.255\n"
        " 20 deny any log\n"
        "ip access-list extended EDGE-IN\n"
        " 10 permit tcp 10.20.100.0 0.0.0.255 any eq 22\n"
        " 20 permit tcp any any eq 3389\n"
        " 30 permit tcp any host 10.20.5.10 eq 443\n"
        " 40 permit tcp any host 10.20.5.10 eq 443\n"
        " 50 deny ip any any log\n"
        "!\n"
        "banner motd ^C Authorized access only. Activity is monitored. ^C\n"
        "!\n"
        "line con 0\n"
        " exec-timeout 5 0\n"
        "line vty 0 4\n"
        " access-class MGMT-ONLY in\n"
        " exec-timeout 10 0\n"
        " transport input ssh\n"
        "line vty 5 15\n"
        " exec-timeout 30 0\n"
        " transport input ssh telnet\n"
        "!\n"
        "end\n"
    ),
    "show interfaces switchport": (
        "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: static access\n"
        "Operational Mode: static access\nAccess Mode VLAN: 10 (CORPORATE)\n!\n"
        "Name: Gi1/0/2\nSwitchport: Enabled\nAdministrative Mode: static access\n"
        "Operational Mode: static access\nAccess Mode VLAN: 1 (default)\n!\n"
        "Name: Gi1/0/3\nSwitchport: Enabled\nAdministrative Mode: static access\n"
        "Operational Mode: static access\nAccess Mode VLAN: 1 (default)\n!\n"
        "Name: Gi1/0/24\nSwitchport: Enabled\nAdministrative Mode: trunk\nOperational Mode: trunk\n"
    ),
    "show spanning-tree summary": (
        "Switch is in rapid-pvst mode\nRoot bridge for: none\nPortFast BPDU Guard Default is enabled\n"
    ),
    "show port-security": (
        "Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action\n"
        "      Gi1/0/1              1            1                  0         Restrict\n"
        "Port Security : Enabled\n"
    ),
    "show vlan brief": (
        "VLAN Name                             Status    Ports\n"
        "---- -------------------------------- --------- -------------------------------\n"
        "1    default                          active    Gi1/0/2, Gi1/0/3\n"
        "10   CORPORATE                        active    Gi1/0/1\n"
        "99   MGMT                             active\n"
    ),
    "show interfaces status": (
        "Port         Name               Status       Vlan       Duplex  Speed Type\n"
        "Gi1/0/1      user-pc            connected    10         a-full a-1000 10/100/1000BaseTX\n"
        "Gi1/0/2                         notconnect   1            auto   auto 10/100/1000BaseTX\n"
        "Gi1/0/3                         notconnect   1            auto   auto 10/100/1000BaseTX\n"
        "Gi1/0/4                         disabled     999          auto   auto 10/100/1000BaseTX\n"
        "Gi1/0/24     uplink             connected    trunk      a-full a-1000 10/100/1000BaseTX\n"
    ),
    # ---------------- Fortinet FortiGate 100F (FortiOS 7.4) ----------------
    "get system status": (
        "Version: FortiGate-100F v7.4.3,build2573,240201 (GA.F)\n"
        "Serial-Number: FG100FTK00000000\n"
        "Hostname: edge-fw-01\n"
        "Virtual domain configuration: disable\n"
    ),
    "get system global": (
        "admin-https-redirect: enable\n"
        "admin-sport        : 8443\n"
        "admin-ssh-port     : 22\n"
        "admin-lockout-threshold: 3\n"
        "admin-lockout-duration: 60\n"
        "admintimeout       : 30\n"
        "pre-login-banner   : enable\n"
        "strong-crypto      : enable\n"
        "hostname           : edge-fw-01\n"
    ),
    "get system admin settings": "admin-https-redirect: enable\n",
    "show firewall policy": (
        "config firewall policy\n"
        "    edit 1\n"
        '        set name "LAN-to-Internet"\n'
        '        set srcintf "internal"\n'
        '        set dstintf "wan1"\n'
        '        set srcaddr "LAN-NET"\n'
        '        set dstaddr "all"\n'
        "        set action accept\n"
        '        set service "HTTP" "HTTPS" "DNS"\n'
        "        set logtraffic all\n"
        "    next\n"
        "    edit 2\n"
        '        set name "Web-DMZ"\n'
        '        set srcintf "wan1"\n'
        '        set dstintf "dmz"\n'
        '        set srcaddr "all"\n'
        '        set dstaddr "WEB-SRV"\n'
        "        set action accept\n"
        '        set service "HTTPS"\n'
        "        set logtraffic all\n"
        "    next\n"
        "    edit 3\n"
        '        set name "Web-DMZ-legacy"\n'
        '        set srcintf "wan1"\n'
        '        set dstintf "dmz"\n'
        '        set srcaddr "all"\n'
        '        set dstaddr "WEB-SRV"\n'
        "        set action accept\n"
        '        set service "HTTPS"\n'
        "    next\n"
        "    edit 4\n"
        '        set name "Vendor-RDP"\n'
        '        set srcintf "wan1"\n'
        '        set dstintf "internal"\n'
        '        set srcaddr "all"\n'
        '        set dstaddr "TERM-SRV"\n'
        "        set action accept\n"
        '        set service "RDP"\n'
        "    next\n"
        "    edit 5\n"
        '        set name "DEFAULT-DENY"\n'
        '        set srcintf "any"\n'
        '        set dstintf "any"\n'
        '        set srcaddr "all"\n'
        '        set dstaddr "all"\n'
        "        set action deny\n"
        '        set service "ALL"\n'
        "        set logtraffic all\n"
        "    next\n"
        "end\n"
    ),
    "get system interface": (
        "== [ internal ]\n"
        "name: internal   mode: static   ip: 10.20.0.1 255.255.255.0   status: up   allowaccess: ping https ssh   type: hard-switch\n"
        "== [ wan1 ]\n"
        "name: wan1   mode: static   ip: 203.0.113.10 255.255.255.248   status: up   allowaccess: ping https http   type: physical\n"
        "== [ dmz ]\n"
        "name: dmz   mode: static   ip: 10.20.5.1 255.255.255.0   status: up   allowaccess: ping   type: physical\n"
    ),
    "get log syslogd setting": "status             : enable\nserver             : 10.20.100.5\nport               : 514\n",
    "show system ntp": "config system ntp\n    set ntpsync enable\n    set type custom\nend\n",
    "show system snmp community": 'config system snmp community\n    edit 1\n        set name "public"\n    next\nend\n',
    "show system snmp user": "config system snmp user\nend\n",
    "show system password-policy": "config system password-policy\n    set status enable\n    set minimum-length 12\nend\n",
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
        exit_code = 0
        if resp is None:
            # Unknown commands fail like a real device instead of returning another
            # device's output.
            resp = f"% Unknown command: {cmd_str}\n"
            exit_code = 1

        def _send():
            time.sleep(0.02)
            try:
                channel.sendall(resp.encode("utf-8"))
                channel.send_exit_status(exit_code)
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
        channel.sendall(b"\r\ncore-sw-01# ")
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
                        if res is not None:
                            channel.sendall(b"\r\n" + res.replace("\n", "\r\n").encode("utf-8"))
                        else:
                            channel.sendall(b"\r\n% Invalid input detected at '^' marker.\r\n")
                    channel.sendall(b"\r\ncore-sw-01# ")
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
        except (OSError, paramiko.SSHException, EOFError, TimeoutError):
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
    print("  [+] Simulates: Ubuntu 22.04 LTS, Cisco Catalyst 9300 (IOS XE 17.12), FortiGate 100F (FortiOS 7.4)")
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
