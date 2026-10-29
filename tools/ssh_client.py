"""Simple interactive terminal client to connect to the BaselineGuard Mock Target.

Usage:
    python tools/ssh_client.py
"""

import sys
import time
import paramiko

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("[*] Connecting to BaselineGuard Mock SSH Target at 127.0.0.1:2222...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect("127.0.0.1", port=2222, username="audituser", password="auditpass", timeout=5)
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("[!] Ensure the daemon is running: .\\.venv\\Scripts\\python.exe tools/mock_targets.py")
        return

    chan = client.invoke_shell()
    time.sleep(0.3)
    initial = chan.recv(2048).decode("utf-8", errors="replace")
    sys.stdout.write(initial)
    sys.stdout.flush()

    try:
        while not chan.closed:
            cmd = input()
            chan.send(cmd + "\r")
            time.sleep(0.2)
            out = ""
            while chan.recv_ready():
                out += chan.recv(2048).decode("utf-8", errors="replace")
            sys.stdout.write(out)
            sys.stdout.flush()
            if cmd.strip() in ("exit", "quit"):
                break
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        chan.close()
        client.close()
        print("\n[*] Disconnected.")

if __name__ == "__main__":
    main()

