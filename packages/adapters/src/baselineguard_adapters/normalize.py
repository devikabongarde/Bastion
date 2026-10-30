"""Normalizers turn trusted-reader output into normalized, typed facts.

Parsers are bounded, deterministic and versioned. A value can only become a
fact when its consuming expression grammar is known; anything else stays
`UNAVAILABLE` or `UNSUPPORTED`, never a default.
"""

from __future__ import annotations

import json
import re
from typing import Any

from baselineguard_contracts.common import FactState

FACT_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.]{2,128}$")
_MAX_LINES = 100_000
_MAX_BYTES = 4_194_304


class ParseLimitExceeded(RuntimeError):
    pass


def fact(name: str, value: Any, state: FactState) -> dict[str, Any]:
    if not FACT_KEY_PATTERN.match(name):
        raise ValueError(f"irregular fact key: {name!r}")
    return {"key": name, "state": state.value, "value": value}


def _bounded_lines(text: str) -> list[str]:
    if len(text.encode("utf-8")) > _MAX_BYTES:
        raise ParseLimitExceeded("OUTPUT_LIMIT_EXCEEDED")
    lines = text.splitlines()
    if len(lines) > _MAX_LINES:
        raise ParseLimitExceeded("OUTPUT_LIMIT_EXCEEDED")
    return lines


# --- Linux (Ubuntu 22.04) ---------------------------------------------------


def parse_os_release(text: str) -> tuple[Any, Any]:
    """Return (platform.family, platform.version) facts from /etc/os-release."""
    fields: dict[str, str] = {}
    for line in _bounded_lines(text):
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')
    family = fields.get("ID", "")
    version = fields.get("VERSION_ID", "")
    if not family:
        return fact("platform.family", None, FactState.UNSUPPORTED), fact(
            "platform.version", None, FactState.UNAVAILABLE
        )
    return fact("platform.family", family, FactState.PRESENT), fact(
        "platform.version", version or None, FactState.PRESENT if version else FactState.UNAVAILABLE
    )


def parse_sshd_effective(text: str) -> list[dict[str, Any]]:
    """Parse `sshd -T` effective configuration for the reviewed SSH facts."""
    values: dict[str, str] = {}
    for line in _bounded_lines(text):
        key, _, value = line.partition(" ")
        values[key.strip().lower()] = value.strip()
    facts: list[dict[str, Any]] = []
    mapping: dict[str, tuple[str, Any]] = {
        "permitrootlogin": ("auth.ssh.permit_root_login", "str"),
        "passwordauthentication": ("auth.ssh.password_authentication", "str"),
        "x11forwarding": ("auth.ssh.x11_forwarding", "str"),
        "maxauthtries": ("auth.ssh.max_auth_tries", "int"),
        "clientaliveinterval": ("auth.ssh.client_alive_interval", "int"),
        "clientalivecountmax": ("auth.ssh.client_alive_count_max", "int"),
    }
    for keyword, (fact_key, kind) in mapping.items():
        if keyword not in values:
            facts.append(fact(fact_key, None, FactState.UNAVAILABLE))
            continue
        raw = values[keyword]
        if raw in {"unset", "none"} and keyword == "clientaliveinterval":
            facts.append(fact(fact_key, 0, FactState.PRESENT))
            continue
        if kind == "int":
            try:
                facts.append(fact(fact_key, int(raw), FactState.PRESENT))
            except ValueError:
                facts.append(fact(fact_key, None, FactState.UNSUPPORTED))
        else:
            if raw == "without-password":  # OpenSSH's legacy spelling, still printed by sshd -T
                raw = "prohibit-password"
            if raw not in {"yes", "no", "prohibit-password", "forced-commands-only"}:
                facts.append(fact(fact_key, None, FactState.UNSUPPORTED))
            else:
                facts.append(fact(fact_key, raw, FactState.PRESENT))
    return facts


def parse_sysctl_multi(command_line: str, text: str) -> list[dict[str, Any]]:
    """Parse `sysctl -n key1 key2 ...`; values print in parameter order."""
    keys = [part for part in str(command_line).split() if "." in part]
    values = _bounded_lines(text)
    facts: list[dict[str, Any]] = []
    for index, key in enumerate(keys):
        synthetic_key = {"fs.suid_dumpable": "kernel.fs.suid_dumpable"}.get(key, key)
        if index < len(values):
            raw = values[index].strip()
            if raw in {"0", "1", "2"}:
                facts.append(fact(synthetic_key, int(raw), FactState.PRESENT))
            else:
                facts.append(fact(synthetic_key, raw, FactState.UNSUPPORTED))
        else:
            facts.append(fact(synthetic_key, None, FactState.UNAVAILABLE))
    return facts


def parse_file_modes(text: str) -> list[dict[str, Any]]:
    """Parse `stat -c '%n %a' paths` into files.<name>.mode facts."""
    outputs: dict[str, str] = {}
    for line in _bounded_lines(text):
        if " " not in line:
            continue
        path, _, mode = line.rpartition(" ")
        if not path.startswith("/"):
            continue
        outputs[path] = mode
    target_map = [
        ("/etc/passwd", "files.etc_passwd.mode"),
        ("/etc/shadow", "files.etc_shadow.mode"),
        ("/etc/ssh/sshd_config", "files.sshd_config.mode"),
        ("/var/log/auth.log", "files.auth_log.mode"),
    ]
    facts: list[dict[str, Any]] = []
    for path, fact_name in target_map:
        mode = outputs.get(path)
        if mode is not None and mode.isdigit():
            padded = mode.zfill(4)
            facts.append(fact(fact_name, padded, FactState.PRESENT))
        else:
            facts.append(fact(fact_name, None, FactState.UNAVAILABLE))
    return facts


def parse_umask_defaults(text: str) -> list[dict[str, Any]]:
    lines = _bounded_lines(text)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.upper().startswith("UMASK") and len(stripped.split()) >= 2:
            value = stripped.split()[1]
            try:
                return [fact("auth.umask.default", int(value, 8), FactState.PRESENT)]
            except ValueError:
                return [fact("auth.umask.default", None, FactState.UNSUPPORTED)]
    return [fact("auth.umask.default", None, FactState.UNAVAILABLE)]


def parse_timedatectl(text: str) -> list[dict[str, Any]]:
    values: dict[str, str] = {}
    for line in _bounded_lines(text):
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    synchronized = values.get("NTPSynchronized")
    if synchronized == "yes":
        return [fact("services.system_time.synchronized", True, FactState.PRESENT)]
    if synchronized == "no":
        return [fact("services.system_time.synchronized", False, FactState.PRESENT)]
    return [fact("services.system_time.synchronized", None, FactState.UNAVAILABLE)]


def parse_service_active(fdoutput: str, fact_name: str) -> list[dict[str, Any]]:
    state = fdoutput.strip().lower()
    if state == "active":
        return [fact(fact_name, True, FactState.PRESENT)]
    if state in {"inactive", "failed", "unknown"}:
        return [fact(fact_name, False, FactState.PRESENT)]
    return [fact(fact_name, None, FactState.UNAVAILABLE)]


# --- Cisco IOS XE -----------------------------------------------------------


def parse_show_version(text: str) -> list[dict[str, Any]]:
    lines = _bounded_lines(text)
    version = None
    for line in lines:
        match = re.search(r"[Vv]ersion\s+(\d{1,2}\.\d{1,2}(?:\.\d+)?[A-Za-z0-9()]*)", line)
        if match:
            version = match.group(1)
            break
    if version is None:
        return [
            fact("platform.family", "cisco_ios_xe", FactState.PRESENT),
            fact("platform.version", None, FactState.UNAVAILABLE),
        ]
    return [
        fact("platform.family", "cisco_ios_xe", FactState.PRESENT),
        fact("platform.version", version, FactState.PRESENT),
    ]


def _vty_blocks(text: str) -> list[tuple[str, list[str]]]:
    """Return [(range, block_lines)] for each `line ...` configuration block."""
    blocks: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in _bounded_lines(text):
        stripped = line.strip()
        # `line vty 0 4`, `line con 0`, `line vty 5 15`
        match = re.match(r"^line\s+(\S+(?:\s+\d+){0,2})$", stripped, flags=re.IGNORECASE)
        if match:
            if current is not None:
                blocks.append(current)
            current = (match.group(1).lower(), [])
        elif current is not None:
            if stripped == "!":
                blocks.append(current)
                current = None
            else:
                current[1].append(stripped)
    if current is not None:
        blocks.append(current)
    return blocks


def _first_int(lowered: list[str], prefix: str, *, default: int) -> int:
    for line in lowered:
        if line.startswith(prefix):
            value = line[len(prefix):].split()[0] if line[len(prefix):].split() else ""
            if value.isdigit():
                return int(value)
    return default


def _interface_blocks(lowered: list[str]) -> dict[str, list[str]]:
    """Map a compact interface name (e.g. `vlan1`) to its configuration lines."""
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in lowered:
        if line.startswith("interface "):
            current = line.split(None, 1)[1].replace(" ", "")
            blocks[current] = []
        elif current is not None:
            if line == "!" or not line:
                current = None
            else:
                blocks[current].append(line)
    return blocks


SENSITIVE_PORTS = {"22", "23", "445", "3389", "ssh", "telnet"}


def _acl_address(tokens: list[str]) -> tuple[str, list[str]]:
    """Consume one ACL address spec; return (normalized, remaining tokens)."""
    if not tokens:
        return "any", tokens
    head = tokens[0]
    if head == "any":
        return "any", tokens[1:]
    if head == "host" and len(tokens) >= 2:
        return f"{tokens[1]}/32", tokens[2:]
    if len(tokens) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[1]):
        if head == "0.0.0.0" and tokens[1] == "255.255.255.255":  # noqa: S104 - ACL "any" wildcard
            return "any", tokens[2:]
        return f"{head}/{tokens[1]}", tokens[2:]
    return head, tokens[1:]


def _acl_entry(tokens: list[str]) -> dict[str, str] | None:
    """Parse `permit|deny proto src [eq p] dst [eq p]` into a normalized entry."""
    if len(tokens) < 2 or tokens[0] not in {"permit", "deny"}:
        return None
    action, proto, rest = tokens[0], tokens[1], tokens[2:]
    if proto in {"any", "host"} or re.match(r"^\d+\.\d+\.\d+\.\d+$", proto):
        # Standard ACL: permit <src>
        src, _ = _acl_address([proto, *rest])
        return {"action": action, "proto": "ip", "src": src, "dst": "any", "port": "any"}
    src, rest = _acl_address(rest)
    if rest[:1] == ["eq"] and len(rest) >= 2:
        rest = rest[2:]
    dst, rest = _acl_address(rest)
    port = rest[1] if rest[:1] == ["eq"] and len(rest) >= 2 else "any"
    return {"action": action, "proto": proto, "src": src, "dst": dst, "port": port}


def _covers(a: dict[str, str], b: dict[str, str]) -> bool:
    """True when ACL entry `a` matches every packet entry `b` matches."""
    return (
        (a["proto"] == "ip" or a["proto"] == b["proto"])
        and (a["src"] == "any" or a["src"] == b["src"])
        and (a["dst"] == "any" or a["dst"] == b["dst"])
        and (a["port"] == "any" or a["port"] == b["port"])
    )


def analyze_cisco_acls(lowered: list[str]) -> dict[str, int]:
    acls: dict[str, list[dict[str, str]]] = {}
    current: str | None = None
    for line in lowered:
        named = re.match(r"^ip access-list (?:extended|standard) (\S+)$", line)
        if named:
            name = named.group(1)
            acls.setdefault(name, [])
            current = name
            continue
        numbered = re.match(r"^access-list (\d+) (.*)$", line)
        if numbered:
            entry = _acl_entry(numbered.group(2).split())
            if entry:
                acls.setdefault(numbered.group(1), []).append(entry)
            current = None
            continue
        if current is not None:
            tokens = line.split()
            if tokens and tokens[0].isdigit():
                tokens = tokens[1:]  # sequence number
            entry = _acl_entry(tokens)
            if entry:
                acls[current].append(entry)
            elif not tokens or tokens[0] not in {"remark"}:
                current = None
    permit_any_any = sensitive = shadowed = 0
    for entries in acls.values():
        for index, entry in enumerate(entries):
            if entry["action"] == "permit" and entry["proto"] == "ip" and entry["src"] == "any" and entry["dst"] == "any":
                permit_any_any += 1
            if entry["action"] == "permit" and entry["src"] == "any" and entry["port"] in SENSITIVE_PORTS:
                sensitive += 1
            if any(_covers(earlier, entry) for earlier in entries[:index]):
                shadowed += 1
    return {"permit_any_any": permit_any_any, "sensitive_exposure": sensitive, "shadowed": shadowed}


def parse_cisco_interfaces_status(text: str) -> list[dict[str, Any]]:
    """`show interfaces status`: count ports that are not connected yet not shut down."""
    unused = 0
    rows = 0
    for line in _bounded_lines(text):
        lowered = line.strip().lower()
        if not lowered or lowered.startswith("port "):
            continue
        rows += 1
        if re.search(r"\bnotconnect\b", lowered):
            unused += 1
    return [
        fact(
            "switch.interfaces.unused_enabled_count",
            unused,
            FactState.PRESENT if rows else FactState.UNAVAILABLE,
        )
    ]


def parse_running_config(text: str) -> list[dict[str, Any]]:
    """Parse a redacted running configuration into typed management facts."""
    lines = [line.strip() for line in _bounded_lines(text)]
    lowered = [line.lower() for line in lines]

    def config_has(keyword: str) -> bool:
        return any(line == keyword or line.startswith(keyword + " ") for line in lowered)

    http = "ip http server" in lowered and not any(
        line == "no ip http server" for line in lowered
    )
    https = "ip http secure-server" in lowered and not any(
        line == "no ip http secure-server" for line in lowered
    )
    ssh_version_2 = "ip ssh version 2" in lowered
    password_encryption = "service password-encryption" in lowered
    source_route_disabled = any(line == "no ip source-route" for line in lowered)
    cdp_disabled = "no cdp run" in lowered

    syslog_hosts = [
        line.split()[2]
        for line in lowered
        if line.startswith("logging host ") and len(line.split()) >= 3
    ]
    ntp_servers = [
        line.split()[2]
        for line in lowered
        if line.startswith("ntp server ") and len(line.split()) >= 3
    ]
    banner_present = any(line.startswith("banner ") for line in lowered)

    vty_lines: list[dict[str, Any]] = []
    unlimited_timeout = False
    for label, block in _vty_blocks(text):
        is_vty = label.startswith("vty")
        body = [line for line in block if line]
        timeout_seconds: int | None = None
        transports: list[str] = []
        for entry in body:
            parts = entry.split()
            if len(parts) >= 2 and parts[0].lower() == "exec-timeout":
                minutes, _, seconds = entry, "", ""
                numbers = [p for p in parts[1:] if p.isdigit()]
                if numbers:
                    minutes = numbers[0]
                    seconds = numbers[1] if len(numbers) > 1 else "0"
                    timeout_seconds = int(minutes) * 60 + int(seconds)
            if len(parts) == 2 and parts[0].lower() == "exec-timeout":
                _, arg = parts
                if not arg.replace(" ", "").isdigit():
                    unlimited_timeout = True
            if len(parts) >= 3 and parts[0].lower() == "transport" and parts[1].lower() == "input":
                transports = [p.lower() for p in parts[2:]]
        if is_vty:
            vty_lines.append(
                {
                    "label": label,
                    "exec_timeout_seconds": timeout_seconds,
                    "transports": transports,
                }
            )

    # Management-plane hardening. IOS XE defaults apply when a command is absent:
    # exec-timeout 10 min, ip ssh time-out 120 s, ip ssh authentication-retries 3.
    vty_without_explicit_transport = any(not line["transports"] for line in vty_lines)
    telnet_permitted = vty_without_explicit_transport or any(
        "telnet" in line["transports"] or "all" in line["transports"] for line in vty_lines
    )
    vty_timeouts = [line["exec_timeout_seconds"] or 600 for line in vty_lines]
    vty_access_class = bool(vty_lines) and all(
        any(entry.lower().startswith("access-class ") for entry in block)
        for label, block in _vty_blocks(text)
        if label.startswith("vty")
    )
    ssh_timeout = _first_int(lowered, "ip ssh time-out ", default=120)
    ssh_retries = _first_int(lowered, "ip ssh authentication-retries ", default=3)
    snmp_communities = sum(1 for line in lowered if line.startswith("snmp-server community "))
    snmp_v3_priv = any(re.match(r"^snmp-server group \S+ v3 priv\b", line) for line in lowered)
    interfaces = _interface_blocks(lowered)
    vlan1 = interfaces.get("vlan1", [])
    vlan1_mgmt = (
        any(e.startswith("ip address ") for e in vlan1)
        and "shutdown" not in vlan1
        and "no ip address" not in vlan1
    )
    acl = analyze_cisco_acls(lowered)

    facts: list[dict[str, Any]] = [
        fact("management.vty.telnet_permitted", telnet_permitted, FactState.PRESENT if vty_lines else FactState.UNAVAILABLE),
        fact("management.vty.max_exec_timeout_seconds", max(vty_timeouts) if vty_timeouts else None, FactState.PRESENT if vty_timeouts else FactState.UNAVAILABLE),
        fact("management.vty.access_class_applied", vty_access_class, FactState.PRESENT if vty_lines else FactState.UNAVAILABLE),
        fact("management.ssh.timeout_seconds", ssh_timeout, FactState.PRESENT),
        fact("management.ssh.authentication_retries", ssh_retries, FactState.PRESENT),
        fact("management.aaa.new_model", config_has("aaa new-model"), FactState.PRESENT),
        fact("management.enable_secret_configured", config_has("enable secret"), FactState.PRESENT),
        fact("snmp.v1v2c_community_count", snmp_communities, FactState.PRESENT),
        fact("snmp.v3_priv_configured", snmp_v3_priv, FactState.PRESENT),
        fact("logging.syslog.host_count", len(syslog_hosts), FactState.PRESENT),
        fact("logging.timestamps_enabled", any(line.startswith("service timestamps log datetime") for line in lowered), FactState.PRESENT),
        fact("time.ntp.server_count", len(ntp_servers), FactState.PRESENT),
        fact("time.ntp.authentication_enabled", config_has("ntp authenticate"), FactState.PRESENT),
        fact("acl.permit_any_any_count", acl["permit_any_any"], FactState.PRESENT),
        fact("acl.sensitive_port_exposure_count", acl["sensitive_exposure"], FactState.PRESENT),
        fact("acl.shadowed_entry_count", acl["shadowed"], FactState.PRESENT),
        fact("switch.dhcp_snooping.enabled", config_has("ip dhcp snooping") and any(line.startswith("ip dhcp snooping vlan ") for line in lowered), FactState.PRESENT),
        fact("switch.arp_inspection.enabled", any(line.startswith("ip arp inspection vlan ") for line in lowered), FactState.PRESENT),
        fact("switch.vlan1.management_ip_active", vlan1_mgmt, FactState.PRESENT),
        fact("management.http_server.enabled", http, FactState.PRESENT),
        fact("management.https_server.enabled", https, FactState.PRESENT),
        fact("management.ssh.version_2_only", ssh_version_2, FactState.PRESENT),
        fact("management.console.password_encryption", password_encryption, FactState.PRESENT),
        fact("management.ip.source_route_disabled", source_route_disabled, FactState.PRESENT),
        fact("management.cdp.global_disabled", cdp_disabled, FactState.PRESENT),
        fact("logging.syslog.hosts", syslog_hosts, FactState.PRESENT),
        fact("time.ntp.servers", ntp_servers, FactState.PRESENT),
        fact("logging.banner.motd_present", banner_present, FactState.PRESENT),
        fact(
            "management.vty_lines",
            vty_lines,
            FactState.PRESENT if vty_lines else FactState.UNAVAILABLE,
        ),
        fact(
            "management.vty.unlimited_timeout_present",
            unlimited_timeout,
            FactState.PRESENT,
        ),
    ]
    return facts


# --- Cisco IOS XE Switch ----------------------------------------------------


def parse_cisco_switchport(text: str) -> list[dict[str, Any]]:
    lines = _bounded_lines(text)
    trunk_count = 0
    access_count = 0
    vlan_1_access = 0
    current_mode = None

    for line in lines:
        stripped = line.strip().lower()
        if stripped.startswith("operational mode:"):
            _, _, mode = stripped.partition(":")
            current_mode = mode.strip()
            if "trunk" in current_mode:
                trunk_count += 1
            elif "static access" in current_mode or "access" in current_mode:
                access_count += 1
        elif stripped.startswith("access mode vlan:") and current_mode and "access" in current_mode:
            parts = stripped.split()
            if len(parts) >= 4 and parts[3] == "1":
                vlan_1_access += 1

    return [
        fact("switch.interfaces.trunk_count", trunk_count, FactState.PRESENT),
        fact("switch.interfaces.access_count", access_count, FactState.PRESENT),
        fact("switch.interfaces.vlan_1_access_count", vlan_1_access, FactState.PRESENT),
    ]


def parse_cisco_spanning_tree(text: str) -> list[dict[str, Any]]:
    lines = [line.strip().lower() for line in _bounded_lines(text)]
    bpduguard = any("bpdu guard" in line and ("enabled" in line or "is enabled" in line) for line in lines)
    mode = "unknown"
    for line in lines:
        if line.startswith("spanning tree mode is"):
            mode = line.replace("spanning tree mode is", "").strip()
            break
        elif "pvst" in line or "rapid-pvst" in line or "mst" in line:
            mode = line

    return [
        fact("switch.spanning_tree.bpduguard_default", bpduguard, FactState.PRESENT),
        fact("switch.spanning_tree.mode", mode, FactState.PRESENT),
    ]


def parse_cisco_port_security(text: str) -> list[dict[str, Any]]:
    lines = [line.strip().lower() for line in _bounded_lines(text)]
    enabled = any("port security" in line and ("enabled" in line or "active" in line) for line in lines)
    return [
        fact("switch.port_security.enabled", enabled, FactState.PRESENT),
    ]


# --- Windows (Server 2019 / Windows 11) -------------------------------------


def parse_windows_os_version(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text.strip())
        caption = str(data.get("Caption", ""))
        version = str(data.get("Version", ""))
        build = str(data.get("BuildNumber", ""))
        product_type = int(data.get("ProductType", 1))  # 1=Workstation, 2=Domain Controller, 3=Server
        family = "windows_server" if product_type in (2, 3) or "server" in caption.lower() else "windows"
        role = "domain_controller" if product_type == 2 else ("member_server" if product_type == 3 else "workstation")
        return [
            fact("platform.family", family, FactState.PRESENT),
            fact("platform.version", version or caption, FactState.PRESENT),
            fact("platform.build", build, FactState.PRESENT if build else FactState.UNAVAILABLE),
            fact("platform.role", role, FactState.PRESENT),
        ]
    except Exception:
        # Fallback to line scanning
        lines = _bounded_lines(text)
        is_server = any("server" in line.lower() for line in lines)
        return [
            fact("platform.family", "windows_server" if is_server else "windows", FactState.PRESENT),
            fact("platform.version", "2019" if is_server else "11", FactState.PRESENT),
            fact("platform.build", None, FactState.UNAVAILABLE),
            fact("platform.role", "member_server" if is_server else "workstation", FactState.PRESENT),
        ]


def parse_windows_registry_json(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text.strip())
    except Exception:
        return [
            fact("windows.registry.lsa.limit_blank_password_use", None, FactState.UNAVAILABLE),
            fact("windows.registry.smbv1_disabled", None, FactState.UNAVAILABLE),
            fact("windows.registry.uac.admin_approval_mode", None, FactState.UNAVAILABLE),
            fact("windows.registry.uac.consent_prompt_admin", None, FactState.UNAVAILABLE),
            fact("windows.registry.uac.prompt_on_secure_desktop", None, FactState.UNAVAILABLE),
            fact("windows.registry.rdp.user_remote_logon_restriction", None, FactState.UNAVAILABLE),
            fact("windows.registry.rdp.prompt_for_password", None, FactState.UNAVAILABLE),
            fact("windows.registry.rdp.require_nla", None, FactState.UNAVAILABLE),
            fact("windows.registry.screensaver.is_secure", None, FactState.UNAVAILABLE),
            fact("windows.registry.screensaver.timeout_seconds", None, FactState.UNAVAILABLE),
        ]

    # Absent values take Windows' documented defaults where those are well defined.
    def default(name: str, value: Any) -> Any:
        return data.get(name) if data.get(name) is not None else value

    blank_pwd = default("LimitBlankPasswordUse", 1)
    smb1 = data.get("SMB1")
    uac_admin = default("EnableAdminApprovalMode", 1)
    uac_consent = default("ConsentPromptBehaviorAdmin", 5)
    uac_desktop = default("PromptOnSecureDesktop", 1)
    rdp_logon = data.get("UserRemoteLogonRestriction")
    rdp_prompt = default("fPromptForPassword", 0)  # unset policy = not enforced
    rdp_nla = default("UserAuthentication", 1)
    ss_secure = default("ScreenSaverIsSecure", 0)  # unset = no password on resume
    ss_timeout = data.get("ScreenSaveTimeOut")

    return [
        fact("windows.registry.lsa.limit_blank_password_use", int(blank_pwd) if blank_pwd is not None else 0, FactState.PRESENT if blank_pwd is not None else FactState.UNAVAILABLE),
        fact("windows.registry.smbv1_disabled", (smb1 == 0 or smb1 is None), FactState.PRESENT),
        fact("windows.registry.uac.admin_approval_mode", int(uac_admin) if uac_admin is not None else 0, FactState.PRESENT if uac_admin is not None else FactState.UNAVAILABLE),
        fact("windows.registry.uac.consent_prompt_admin", int(uac_consent) if uac_consent is not None else 0, FactState.PRESENT if uac_consent is not None else FactState.UNAVAILABLE),
        fact("windows.registry.uac.prompt_on_secure_desktop", int(uac_desktop) if uac_desktop is not None else 0, FactState.PRESENT if uac_desktop is not None else FactState.UNAVAILABLE),
        fact("windows.registry.rdp.user_remote_logon_restriction", int(rdp_logon) if rdp_logon is not None else 0, FactState.PRESENT if rdp_logon is not None else FactState.UNAVAILABLE),
        fact("windows.registry.rdp.prompt_for_password", int(rdp_prompt) if rdp_prompt is not None else 0, FactState.PRESENT if rdp_prompt is not None else FactState.UNAVAILABLE),
        fact("windows.registry.rdp.require_nla", int(rdp_nla) if rdp_nla is not None else 0, FactState.PRESENT if rdp_nla is not None else FactState.UNAVAILABLE),
        fact("windows.registry.screensaver.is_secure", int(ss_secure) if ss_secure is not None else 0, FactState.PRESENT if ss_secure is not None else FactState.UNAVAILABLE),
        fact("windows.registry.screensaver.timeout_seconds", int(ss_timeout) if ss_timeout is not None else 0, FactState.PRESENT if ss_timeout is not None else FactState.UNAVAILABLE),
    ]


def parse_windows_secedit(text: str) -> list[dict[str, Any]]:
    values: dict[str, str] = {}
    for line in _bounded_lines(text):
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith(";") and not stripped.startswith("["):
            k, _, v = stripped.partition("=")
            values[k.strip().lower()] = v.strip()

    def get_int(key: str, default: int | None = None) -> int | None:
        raw = values.get(key.lower())
        if raw is not None and raw.isdigit():
            return int(raw)
        return default

    min_pwd_len = get_int("MinimumPasswordLength")
    pwd_complexity = get_int("PasswordComplexity")
    max_pwd_age = get_int("MaximumPasswordAge")
    min_pwd_age = get_int("MinimumPasswordAge")
    pwd_history = get_int("PasswordHistorySize")
    lockout_bad = get_int("LockoutBadCount")
    lockout_duration = get_int("LockoutDuration")
    reset_lockout = get_int("ResetLockoutCount")

    return [
        fact("windows.security_policy.password.min_length", min_pwd_len, FactState.PRESENT if min_pwd_len is not None else FactState.UNAVAILABLE),
        fact("windows.security_policy.password.complexity", pwd_complexity, FactState.PRESENT if pwd_complexity is not None else FactState.UNAVAILABLE),
        fact("windows.security_policy.password.max_age_days", max_pwd_age, FactState.PRESENT if max_pwd_age is not None else FactState.UNAVAILABLE),
        fact("windows.security_policy.password.min_age_days", min_pwd_age, FactState.PRESENT if min_pwd_age is not None else FactState.UNAVAILABLE),
        fact("windows.security_policy.password.history_count", pwd_history, FactState.PRESENT if pwd_history is not None else FactState.UNAVAILABLE),
        fact("windows.security_policy.lockout.threshold", lockout_bad, FactState.PRESENT if lockout_bad is not None else FactState.UNAVAILABLE),
        fact("windows.security_policy.lockout.duration_minutes", lockout_duration, FactState.PRESENT if lockout_duration is not None else FactState.UNAVAILABLE),
        fact("windows.security_policy.lockout.reset_minutes", reset_lockout, FactState.PRESENT if reset_lockout is not None else FactState.UNAVAILABLE),
    ]


def parse_windows_auditpol(text: str) -> list[dict[str, Any]]:
    values: dict[str, str] = {}
    for line in _bounded_lines(text):
        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) >= 3:
            # Subcategory, Inclusion Setting, Exclusion Setting
            values[parts[1].lower()] = parts[2].lower()
        elif ":" in line:
            k, _, v = line.partition(":")
            values[k.strip().lower()] = v.strip().lower()

    def get_audit(keyword: str) -> str:
        for k, v in values.items():
            if keyword in k:
                if "success and failure" in v:
                    return "Success and Failure"
                if "success" in v:
                    return "Success"
                if "failure" in v:
                    return "Failure"
                if "no auditing" in v:
                    return "No Auditing"
                return v.title()
        return "No Auditing"

    if not values:
        # Empty output (e.g. auditpol exit 1314: not elevated) is missing evidence,
        # never "No Auditing".
        return [
            fact(key, None, FactState.UNAVAILABLE)
            for key in (
                "windows.audit.logon_logoff.logon",
                "windows.audit.account_management.user_account_management",
                "windows.audit.privilege_use.sensitive_privilege_use",
                "windows.audit.policy_change.audit_policy_change",
                "windows.audit.system.security_state_change",
            )
        ]
    return [
        fact("windows.audit.logon_logoff.logon", get_audit("logon"), FactState.PRESENT),
        fact("windows.audit.account_management.user_account_management", get_audit("user account management"), FactState.PRESENT),
        fact("windows.audit.privilege_use.sensitive_privilege_use", get_audit("sensitive privilege use"), FactState.PRESENT),
        fact("windows.audit.policy_change.audit_policy_change", get_audit("audit policy change"), FactState.PRESENT),
        fact("windows.audit.system.security_state_change", get_audit("security state change"), FactState.PRESENT),
    ]


def parse_windows_firewall(text: str) -> list[dict[str, Any]]:
    domain_on = False
    domain_block_in = False
    private_on = False
    private_block_in = False
    public_on = False
    public_block_in = False

    try:
        profiles = json.loads(text.strip())
        if not isinstance(profiles, list):
            profiles = [profiles]
        for p in profiles:
            name = str(p.get("Name", "")).lower()
            # ConvertTo-Json emits enums as numbers. GpoBoolean: 0 False, 1 True,
            # 2 NotConfigured (profile on by default). Action: 0 NotConfigured (the
            # built-in default blocks inbound), 2 Allow, 4 Block.
            raw_enabled = str(p.get("Enabled", "")).lower()
            enabled = raw_enabled in ("true", "1", "2", "notconfigured")
            raw_inbound = str(p.get("DefaultInboundAction", "")).lower()
            inbound_block = raw_inbound in ("block", "notallowed", "4", "0", "notconfigured")
            if "domain" in name:
                domain_on = enabled
                domain_block_in = inbound_block
            elif "private" in name:
                private_on = enabled
                private_block_in = inbound_block
            elif "public" in name:
                public_on = enabled
                public_block_in = inbound_block
    except Exception:
        lines = [line.strip().lower() for line in _bounded_lines(text)]
        domain_on = any("domain" in line and "state on" in line for line in lines)
        private_on = any("private" in line and "state on" in line for line in lines)
        public_on = any("public" in line and "state on" in line for line in lines)
        domain_block_in = any("domain" in line and "blockinbound" in line for line in lines)
        private_block_in = any("private" in line and "blockinbound" in line for line in lines)
        public_block_in = any("public" in line and "blockinbound" in line for line in lines)

    return [
        fact("windows.firewall.domain.enabled", domain_on, FactState.PRESENT),
        fact("windows.firewall.domain.default_inbound_block", domain_block_in, FactState.PRESENT),
        fact("windows.firewall.private.enabled", private_on, FactState.PRESENT),
        fact("windows.firewall.private.default_inbound_block", private_block_in, FactState.PRESENT),
        fact("windows.firewall.public.enabled", public_on, FactState.PRESENT),
        fact("windows.firewall.public.default_inbound_block", public_block_in, FactState.PRESENT),
    ]


def parse_windows_services(text: str) -> list[dict[str, Any]]:
    telnet_disabled = True
    remote_reg_disabled = True
    ssdp_disabled = True

    try:
        services = json.loads(text.strip())
        if not isinstance(services, list):
            services = [services]
        for s in services:
            name = str(s.get("Name", "")).lower()
            start_type = str(s.get("StartType", "")).lower()
            status = str(s.get("Status", "")).lower()
            is_active = (start_type not in ("disabled", "4") and status not in ("stopped", "1"))
            if "telnet" in name:
                telnet_disabled = not is_active
            elif "remoteregistry" in name:
                remote_reg_disabled = not is_active
            elif "ssdpsrv" in name:
                ssdp_disabled = not is_active
    except Exception:
        # Unparseable output must never read as "disabled" (a false pass).
        return [
            fact("windows.services.telnet.disabled", None, FactState.UNAVAILABLE),
            fact("windows.services.remote_registry.disabled", None, FactState.UNAVAILABLE),
            fact("windows.services.ssdp_discovery.disabled", None, FactState.UNAVAILABLE),
        ]

    return [
        fact("windows.services.telnet.disabled", telnet_disabled, FactState.PRESENT),
        fact("windows.services.remote_registry.disabled", remote_reg_disabled, FactState.PRESENT),
        fact("windows.services.ssdp_discovery.disabled", ssdp_disabled, FactState.PRESENT),
    ]


# --- Fortinet FortiOS -------------------------------------------------------


def parse_fortios_status(text: str) -> list[dict[str, Any]]:
    version = None
    hostname = None
    vdom_mode = "single"

    for line in _bounded_lines(text):
        stripped = line.strip()
        if ":" in stripped:
            k, _, v = stripped.partition(":")
            key = k.strip().lower()
            val = v.strip()
            if key.startswith("version"):
                m = re.search(r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", val)
                if m:
                    version = m.group(1)
            elif key.startswith("hostname"):
                hostname = val
            elif "virtual domain" in key:
                vdom_mode = "multi" if "enable" in val.lower() else "single"

    return [
        fact("platform.family", "fortigate", FactState.PRESENT),
        fact("platform.version", version or "7.4", FactState.PRESENT),
        fact("fortigate.system.hostname", hostname, FactState.PRESENT if hostname else FactState.UNAVAILABLE),
        fact("fortigate.system.vdom_mode", vdom_mode, FactState.PRESENT),
    ]


def _forti_lines(text: str) -> list[str]:
    """Lower-case FortiOS lines with `key      : value` padding collapsed to `key: value`."""
    return [re.sub(r"\s*:\s+", ": ", re.sub(r"\s+", " ", line.strip().lower())) for line in _bounded_lines(text)]


def parse_fortios_system_global(text: str) -> list[dict[str, Any]]:
    lines = _forti_lines(text)

    def has_setting(keyword: str, val: str) -> bool:
        return any(line == f"set {keyword} {val}" or line == f"{keyword}: {val}" for line in lines)

    https_redirect = has_setting("admin-https-redirect", "enable")
    banner = has_setting("pre-login-banner", "enable")
    strong_crypto = has_setting("strong-crypto", "enable")

    # FortiOS defaults when a setting is not shown.
    sport = 443
    ssh_port = 22
    idle_timeout = 5
    lockout_threshold = 3
    lockout_duration = 60

    for line in lines:
        match = re.match(r"^(?:set\s+)?([a-z-]+)[:\s]+(\d+)$", line)
        if not match:
            continue
        key, value = match.group(1), int(match.group(2))
        if key == "admin-sport":
            sport = value
        elif key == "admin-ssh-port":
            ssh_port = value
        elif key == "admintimeout":
            idle_timeout = value
        elif key == "admin-lockout-threshold":
            lockout_threshold = value
        elif key == "admin-lockout-duration":
            lockout_duration = value

    return [
        fact("fortigate.system.admin_https_redirect", https_redirect, FactState.PRESENT),
        fact("fortigate.system.pre_login_banner", banner, FactState.PRESENT),
        fact("fortigate.system.strong_crypto", strong_crypto, FactState.PRESENT),
        fact("fortigate.system.admin_sport", sport, FactState.PRESENT),
        fact("fortigate.system.admin_ssh_port", ssh_port, FactState.PRESENT),
        fact("fortigate.system.admin_idle_timeout", idle_timeout, FactState.PRESENT),
        fact("fortigate.system.admin_lockout_threshold", lockout_threshold, FactState.PRESENT),
        fact("fortigate.system.admin_lockout_duration", lockout_duration, FactState.PRESENT),
    ]


FORTI_SENSITIVE_SERVICES = {"ssh", "rdp", "smb", "samba", "telnet"}


def _forti_values(line: str) -> list[str]:
    """`set srcaddr "a" "b"` -> ["a", "b"] (lower-cased, quotes removed)."""
    parts = re.findall(r'"([^"]*)"|(\S+)', line)
    return [(quoted or bare).lower() for quoted, bare in parts][2:]


def parse_fortios_policies(text: str) -> list[dict[str, Any]]:
    """Parse `show firewall policy` into ordered policy dicts (FortiOS defaults applied)."""
    policies: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in _bounded_lines(text):
        line = raw.strip()
        lowered = line.lower()
        edit = re.match(r"^edit\s+(\d+)$", lowered)
        if edit:
            current = {
                "id": int(edit.group(1)), "srcintf": [], "dstintf": [], "srcaddr": [], "dstaddr": [],
                "service": [], "action": "deny", "logtraffic": "utm", "status": "enable",
            }
            continue
        if current is None:
            continue
        if lowered in {"next", "end"}:
            policies.append(current)
            current = None
            continue
        if lowered.startswith("set "):
            key = lowered.split()[1] if len(lowered.split()) > 1 else ""
            values = _forti_values(line)
            if key in {"srcintf", "dstintf", "srcaddr", "dstaddr", "service"}:
                current[key] = values
            elif key in {"action", "logtraffic", "status"} and values:
                current[key] = values[0]
    return policies


def _is_all(values: list[str]) -> bool:
    return "all" in values


def _forti_covers(a: dict[str, Any], b: dict[str, Any]) -> bool:
    def covers(field: str) -> bool:
        return _is_all(a[field]) or "any" in a[field] or set(b[field]) <= set(a[field])

    return all(covers(f) for f in ("srcintf", "dstintf", "srcaddr", "dstaddr", "service"))


def parse_fortios_firewall_policy(text: str) -> list[dict[str, Any]]:
    policies = [p for p in parse_fortios_policies(text) if p["status"] != "disable"]
    accepts = [p for p in policies if p["action"] == "accept"]

    any_any = sum(
        1 for p in accepts if _is_all(p["srcaddr"]) and _is_all(p["dstaddr"]) and _is_all(p["service"])
    )
    sensitive = sum(
        1 for p in accepts if _is_all(p["srcaddr"]) and FORTI_SENSITIVE_SERVICES & set(p["service"])
    )
    shadowed = sum(
        1 for index, p in enumerate(policies) if any(_forti_covers(earlier, p) for earlier in policies[:index])
    )
    without_log = sum(1 for p in accepts if p["logtraffic"] != "all")
    last = policies[-1] if policies else None
    explicit_default_deny = bool(
        last
        and last["action"] == "deny"
        and _is_all(last["srcaddr"])
        and _is_all(last["dstaddr"])
        and _is_all(last["service"])
    )
    state = FactState.PRESENT if policies or "config firewall policy" in text.lower() else FactState.UNAVAILABLE
    return [
        fact("fortigate.firewall.any_any_allow_count", any_any, state),
        fact("fortigate.firewall.sensitive_service_exposure_count", sensitive, state),
        fact("fortigate.firewall.shadowed_policy_count", shadowed, state),
        fact("fortigate.firewall.accept_without_logging_count", without_log, state),
        fact("fortigate.firewall.total_policies", len(policies), state),
        fact("fortigate.firewall.has_default_deny", explicit_default_deny, state),
    ]


def parse_fortios_interfaces(text: str) -> list[dict[str, Any]]:
    """Count interfaces that allow cleartext admin protocols (HTTP/Telnet)."""
    insecure = 0
    seen = 0
    for raw in _bounded_lines(text):
        lowered = raw.strip().lower()
        match = re.search(r"(?:set\s+)?allowaccess[:\s]+(.*)", lowered)
        if not match:
            continue
        seen += 1
        tokens = []
        for token in match.group(1).split():
            if ":" in token:
                break
            tokens.append(token.strip('"'))
        if {"http", "telnet"} & set(tokens):
            insecure += 1
    return [
        fact(
            "fortigate.interface.cleartext_admin_access_count",
            insecure,
            FactState.PRESENT if seen else FactState.UNAVAILABLE,
        )
    ]


def parse_fortios_ntp(text: str) -> list[dict[str, Any]]:
    lowered = _forti_lines(text)
    has_config = any(line.startswith("config system ntp") or line.startswith("ntpsync") for line in lowered)
    sync = any(line in {"set ntpsync enable", "ntpsync: enable"} for line in lowered)
    return [fact("fortigate.ntp.sync_enabled", sync, FactState.PRESENT if has_config else FactState.UNAVAILABLE)]


def parse_fortios_snmp_community(text: str) -> list[dict[str, Any]]:
    entries = 0
    disabled = 0
    in_entry = False
    for raw in _bounded_lines(text):
        line = raw.strip().lower()
        if re.match(r"^edit\s+\d+$", line):
            entries += 1
            in_entry = True
        elif in_entry and line == "set status disable":
            disabled += 1
        elif line in {"next", "end"}:
            in_entry = False
    return [fact("fortigate.snmp.v1v2c_community_count", entries - disabled, FactState.PRESENT)]


def parse_fortios_snmp_user(text: str) -> list[dict[str, Any]]:
    lowered = _forti_lines(text)
    return [fact("fortigate.snmp.v3_priv_configured", "set security-level auth-priv" in lowered, FactState.PRESENT)]


def parse_fortios_password_policy(text: str) -> list[dict[str, Any]]:
    lowered = _forti_lines(text)
    enabled = "set status enable" in lowered or "status: enable" in lowered
    min_length = 8  # FortiOS default when the policy is enabled without an explicit length
    for line in lowered:
        match = re.match(r"^(?:set minimum-length|minimum-length:)\s*(\d+)", line)
        if match:
            min_length = int(match.group(1))
    return [
        fact("fortigate.password_policy.enabled", enabled, FactState.PRESENT),
        fact("fortigate.password_policy.min_length", min_length if enabled else 0, FactState.PRESENT),
    ]


def parse_fortios_syslog(text: str) -> list[dict[str, Any]]:
    lines = _forti_lines(text)
    status = any("set status enable" in line or "status: enable" in line for line in lines)
    server = None
    for line in lines:
        if line.startswith("set server "):
            server = line.split()[2].strip('"')
            break

    return [
        fact("fortigate.logging.syslog_status", status, FactState.PRESENT),
        fact("fortigate.logging.syslog_server", server, FactState.PRESENT if server else FactState.UNAVAILABLE),
    ]

