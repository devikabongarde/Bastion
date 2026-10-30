"""Generate the typed rule packs and remediation catalogs for:

1. Windows Server 2019/2022 & Windows 11
2. Cisco IOS XE routers & switches
3. Fortinet FortiGate (FortiOS 7.x)

Every control asserts a real, distinct fact produced by the adapters in
`packages/adapters` and ships exact, copy-able remediation commands. Run:

    python tools/build_rule_packs.py
"""

import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CONTENT = ROOT / "content"
ORIGINAL = CONTENT / "original"
REMEDIATION = CONTENT / "remediation"
SCHEMA_PATH = CONTENT / "schemas" / "rule-pack.schema.json"
PACK_VERSION = "1.1.0"

schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _identity(families: list[str], role: str | None) -> dict:
    facts = {"platform.family": {"state": "PRESENT", "value": families[0]}}
    if role:
        facts["platform.role"] = {"state": "PRESENT", "value": role}
    return facts


def create_control(d: dict, *, families: list[str], platform: str) -> dict:
    """Build one schema-valid control from a definition dict."""
    family_expr = (
        {"op": "eq", "fact": "platform.family", "value": families[0]}
        if len(families) == 1
        else {"op": "in", "fact": "platform.family", "value": families}
    )
    role = d.get("role")
    applicability = (
        {"op": "and", "args": [family_expr, {"op": "eq", "fact": "platform.role", "value": role}]}
        if role
        else family_expr
    )
    fact_key, op, good, bad = d["fact"], d["op"], d["good"], d["bad"]
    cmp_value = d.get("value", good)
    identity_keys = ["platform.family"] + (["platform.role"] if role else [])
    ident = _identity(families, role)
    return {
        "id": d["id"],
        "revision": 1,
        "origin": "organizational",
        "title": d["title"],
        "severity": d["severity"],
        "description": d.get("desc", f"Evaluates `{fact_key}` on {platform}."),
        "rationale": d["why"],
        "applicability": applicability,
        "required_facts": [fact_key, *identity_keys],
        "assertion": {"op": op, "fact": fact_key, "value": cmp_value},
        "expected": {"fact": fact_key, "operator": op, "value": cmp_value},
        "evidence": [fact_key, *identity_keys],
        "remediation_template": d["rem_id"],
        "tests": [
            {"id": "conforming", "expect": "PASS", "facts": {**ident, fact_key: {"state": "PRESENT", "value": good}}},
            {"id": "deviation", "expect": "FAIL", "facts": {**ident, fact_key: {"state": "PRESENT", "value": bad}}},
            {"id": "unavailable", "expect": "UNKNOWN", "facts": {**ident, fact_key: {"state": "UNAVAILABLE"}}},
            {
                "id": "other-family",
                "expect": "NOT_APPLICABLE",
                "facts": {
                    **ident,
                    "platform.family": {"state": "PRESENT", "value": "other_os"},
                    fact_key: {"state": "PRESENT", "value": good},
                },
            },
        ],
    }


def remediation(d: dict, *, authority: str) -> dict:
    return {
        "summary": d["fix"],
        "steps": d["commands"],
        "verify": d["verify"],
        "impact": d.get("impact", "Apply during a maintenance window and confirm management access afterwards."),
        "authority": d.get("authority", authority),
    }


# ============================================================================
# 1. WINDOWS SERVER 2019/2022 & WINDOWS 11
# ============================================================================
PS = "powershell -NoProfile -Command"
SYSTEM_POLICIES = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def reg(path: str, name: str, value, kind: str = "DWord") -> str:
    return f"Set-ItemProperty -Path '{path}' -Name {name} -Value {value} -Type {kind}"


def secedit_set(key: str, value: int) -> list[str]:
    return [
        r"secedit /export /cfg $env:TEMP\secpol.cfg",
        rf"(Get-Content $env:TEMP\secpol.cfg) -replace '^{key}\s*=.*', '{key} = {value}' | Set-Content $env:TEMP\secpol.cfg",
        r"secedit /configure /db $env:windir\security\local.sdb /cfg $env:TEMP\secpol.cfg /areas SECURITYPOLICY",
    ]


def audit(sub: str) -> list[str]:
    return [f'auditpol /set /subcategory:"{sub}" /success:enable /failure:enable']


win_definitions = [
    # Password & account lockout
    dict(id="org.win.pwd.min_length", title="Ensure 'Minimum password length' is set to 14 or more characters", severity="high",
         fact="windows.security_policy.password.min_length", op="gte", good=14, bad=8,
         why="Short passwords are brute-forced quickly.", fix="Require passwords of at least 14 characters.",
         commands=["net accounts /minpwlen:14"], verify="net accounts | findstr /i \"Minimum password length\""),
    dict(id="org.win.pwd.complexity", title="Ensure 'Password must meet complexity requirements' is enabled", severity="high",
         fact="windows.security_policy.password.complexity", op="eq", good=1, bad=0,
         why="Complexity rules block dictionary passwords.", fix="Enable password complexity.",
         commands=secedit_set("PasswordComplexity", 1), verify=r"secedit /export /cfg $env:TEMP\v.cfg; Select-String PasswordComplexity $env:TEMP\v.cfg"),
    dict(id="org.win.pwd.max_age", title="Ensure 'Maximum password age' is 60 or fewer days", severity="medium",
         fact="windows.security_policy.password.max_age_days", op="lte", good=60, bad=90,
         why="Limits the useful life of a compromised password.", fix="Set maximum password age to 60 days.",
         commands=["net accounts /maxpwage:60"], verify="net accounts | findstr /i \"Maximum password age\""),
    dict(id="org.win.pwd.min_age", title="Ensure 'Minimum password age' is at least 1 day", severity="low",
         fact="windows.security_policy.password.min_age_days", op="gte", good=1, bad=0,
         why="Stops users cycling straight back to an old password.", fix="Set minimum password age to 1 day.",
         commands=["net accounts /minpwage:1"], verify="net accounts | findstr /i \"Minimum password age\""),
    dict(id="org.win.pwd.history", title="Ensure 'Enforce password history' is 24 or more passwords", severity="medium",
         fact="windows.security_policy.password.history_count", op="gte", good=24, bad=5,
         why="Prevents password reuse.", fix="Remember the last 24 passwords.",
         commands=["net accounts /uniquepw:24"], verify="net accounts | findstr /i \"history\""),
    dict(id="org.win.lockout.threshold", title="Ensure 'Account lockout threshold' is 5 or fewer invalid attempts", severity="high",
         fact="windows.security_policy.lockout.threshold", op="lte", good=5, bad=10,
         why="Throttles online password guessing.", fix="Lock accounts after 5 failed logons.",
         commands=["net accounts /lockoutthreshold:5"], verify="net accounts | findstr /i \"Lockout threshold\""),
    dict(id="org.win.lockout.duration", title="Ensure 'Account lockout duration' is 15 or more minutes", severity="medium",
         fact="windows.security_policy.lockout.duration_minutes", op="gte", good=15, bad=5,
         why="Keeps locked accounts locked long enough to deter guessing.", fix="Set lockout duration to 15 minutes.",
         commands=["net accounts /lockoutduration:15"], verify="net accounts | findstr /i \"Lockout duration\""),
    dict(id="org.win.lockout.reset", title="Ensure 'Reset account lockout counter after' is 15 or more minutes", severity="medium",
         fact="windows.security_policy.lockout.reset_minutes", op="gte", good=15, bad=5,
         why="Defines the observation window for failed logons.", fix="Reset the lockout counter after 15 minutes.",
         commands=["net accounts /lockoutwindow:15"], verify="net accounts | findstr /i \"Lockout observation window\""),
    # Security options
    dict(id="org.win.sec.limit_blank_pwd", title="Ensure 'Limit local account use of blank passwords to console logon only' is enabled", severity="high",
         fact="windows.registry.lsa.limit_blank_password_use", op="eq", good=1, bad=0,
         why="Blank-password accounts must never be usable over the network.", fix="Restrict blank passwords to console logon.",
         commands=[reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse", 1)],
         verify=r"Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse"),
    dict(id="org.win.sec.smbv1_disable", title="Ensure SMBv1 is disabled", severity="critical",
         fact="windows.registry.smbv1_disabled", op="eq", good=True, bad=False,
         why="SMBv1 is exploited by wormable malware such as WannaCry.", fix="Disable the SMBv1 protocol.",
         commands=["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                   "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"],
         verify="Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol"),
    dict(id="org.win.uac.admin_approval", title="Ensure 'UAC: Run all administrators in Admin Approval Mode' is enabled", severity="high",
         fact="windows.registry.uac.admin_approval_mode", op="eq", good=1, bad=0,
         why="Admin sessions run unelevated until consent is given.", fix="Enable UAC Admin Approval Mode.",
         commands=[reg(SYSTEM_POLICIES, "EnableAdminApprovalMode", 1)],
         verify=f"Get-ItemPropertyValue '{SYSTEM_POLICIES}' -Name EnableAdminApprovalMode"),
    dict(id="org.win.uac.consent_admin", title="Ensure 'UAC: Behavior of the elevation prompt for administrators' prompts", severity="high",
         fact="windows.registry.uac.consent_prompt_admin", op="gte", good=2, bad=0,
         why="Silent elevation lets malware gain admin rights unnoticed.", fix="Prompt for consent on the secure desktop.",
         commands=[reg(SYSTEM_POLICIES, "ConsentPromptBehaviorAdmin", 2)],
         verify=f"Get-ItemPropertyValue '{SYSTEM_POLICIES}' -Name ConsentPromptBehaviorAdmin", value=1),
    dict(id="org.win.uac.secure_desktop", title="Ensure 'UAC: Switch to the secure desktop when prompting' is enabled", severity="medium",
         fact="windows.registry.uac.prompt_on_secure_desktop", op="eq", good=1, bad=0,
         why="Prevents other processes from spoofing or clicking the prompt.", fix="Show elevation prompts on the secure desktop.",
         commands=[reg(SYSTEM_POLICIES, "PromptOnSecureDesktop", 1)],
         verify=f"Get-ItemPropertyValue '{SYSTEM_POLICIES}' -Name PromptOnSecureDesktop"),
    dict(id="org.win.rdp.remote_logon_rest", title="Ensure remote logon restriction for Terminal Services is enforced", severity="high",
         fact="windows.registry.rdp.user_remote_logon_restriction", op="gte", good=1, bad=0,
         why="Limits which accounts may log on remotely.", fix="Enforce remote logon restrictions.",
         commands=[reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server", "UserRemoteLogonRestriction", 1)],
         verify=r"Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name UserRemoteLogonRestriction"),
    dict(id="org.win.rdp.prompt_pwd", title="Ensure 'Always prompt for password upon connection' is enabled for RDP", severity="medium",
         fact="windows.registry.rdp.prompt_for_password", op="eq", good=1, bad=0,
         why="Saved RDP credentials must not grant silent access.", fix="Always prompt for a password on RDP connection.",
         commands=[r"New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Force | Out-Null",
                   reg(r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fPromptForPassword", 1)],
         verify=r"Get-ItemPropertyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fPromptForPassword"),
    dict(id="org.win.rdp.require_nla", title="Ensure Network Level Authentication is required for RDP", severity="high",
         fact="windows.registry.rdp.require_nla", op="eq", good=1, bad=0,
         why="NLA authenticates users before a full RDP session is created.", fix="Require NLA for Remote Desktop.",
         commands=[reg(r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1)],
         verify=r"Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication"),
    dict(id="org.win.scr.is_secure", title="Ensure 'Password protect the screen saver' is enabled", severity="medium",
         fact="windows.registry.screensaver.is_secure", op="eq", good=1, bad=0,
         why="Unattended sessions must require a password to resume.", fix="Password-protect the screen saver.",
         commands=[reg(r"HKCU:\Control Panel\Desktop", "ScreenSaverIsSecure", '"1"', "String")],
         verify=r"Get-ItemPropertyValue 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure"),
    dict(id="org.win.scr.timeout", title="Ensure 'Screen saver timeout' is 900 or fewer seconds", severity="medium",
         fact="windows.registry.screensaver.timeout_seconds", op="lte", good=900, bad=1800,
         why="Idle sessions lock within 15 minutes.", fix="Lock idle sessions after 15 minutes.",
         commands=[reg(r"HKCU:\Control Panel\Desktop", "ScreenSaveTimeOut", '"900"', "String")],
         verify=r"Get-ItemPropertyValue 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut"),
    # Windows Defender Firewall
    *[
        dict(id=f"org.win.fw.{p.lower()}_state", title=f"Ensure Windows Defender Firewall {p} profile is On",
             severity="critical" if p == "Public" else "high",
             fact=f"windows.firewall.{p.lower()}.enabled", op="eq", good=True, bad=False,
             why=f"The {p} profile must filter traffic.", fix=f"Turn on the {p} firewall profile.",
             commands=[f"Set-NetFirewallProfile -Profile {p} -Enabled True"],
             verify=f"Get-NetFirewallProfile -Profile {p} | Select-Object Name, Enabled")
        for p in ("Domain", "Private", "Public")
    ],
    *[
        dict(id=f"org.win.fw.{p.lower()}_inbound", title=f"Ensure Windows Defender Firewall {p} profile blocks inbound by default",
             severity="critical" if p == "Public" else "high",
             fact=f"windows.firewall.{p.lower()}.default_inbound_block", op="eq", good=True, bad=False,
             why="Unsolicited inbound connections must be denied unless explicitly allowed.",
             fix=f"Block inbound connections by default on the {p} profile.",
             commands=[f"Set-NetFirewallProfile -Profile {p} -DefaultInboundAction Block"],
             verify=f"Get-NetFirewallProfile -Profile {p} | Select-Object Name, DefaultInboundAction")
        for p in ("Domain", "Private", "Public")
    ],
    # Services
    dict(id="org.win.svc.telnet", title="Ensure the Telnet server is disabled or not installed", severity="critical",
         fact="windows.services.telnet.disabled", op="eq", good=True, bad=False,
         why="Telnet sends credentials in cleartext.", fix="Remove the Telnet server.",
         commands=["Stop-Service TlntSvr -ErrorAction SilentlyContinue",
                   "Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer -NoRestart"],
         verify="Get-Service TlntSvr -ErrorAction SilentlyContinue"),
    dict(id="org.win.svc.remotereg", title="Ensure the Remote Registry service is disabled", severity="high",
         fact="windows.services.remote_registry.disabled", op="eq", good=True, bad=False,
         why="Remote Registry exposes configuration to the network.", fix="Disable Remote Registry.",
         commands=["Stop-Service RemoteRegistry -Force", "Set-Service RemoteRegistry -StartupType Disabled"],
         verify="Get-Service RemoteRegistry | Select-Object Status, StartType"),
    dict(id="org.win.svc.ssdp", title="Ensure the SSDP Discovery service is disabled", severity="medium",
         fact="windows.services.ssdp_discovery.disabled", op="eq", good=True, bad=False,
         why="SSDP/UPnP is abused for discovery and amplification.", fix="Disable SSDP Discovery.",
         commands=["Stop-Service SSDPSRV -Force", "Set-Service SSDPSRV -StartupType Disabled"],
         verify="Get-Service SSDPSRV | Select-Object Status, StartType"),
    # Advanced audit policy
    *[
        dict(id=cid, title=f"Ensure 'Audit {sub}' includes Success and Failure", severity=sev, fact=fact,
             op="eq", good="Success and Failure", bad="No Auditing",
             why="Security-relevant events must be recorded for investigation.", fix=f"Audit {sub} success and failure.",
             commands=audit(sub), verify=f'auditpol /get /subcategory:"{sub}"')
        for cid, sub, sev, fact in (
            ("org.win.audit.logon", "Logon", "high", "windows.audit.logon_logoff.logon"),
            ("org.win.audit.user_mgmt", "User Account Management", "high", "windows.audit.account_management.user_account_management"),
            ("org.win.audit.priv_use", "Sensitive Privilege Use", "high", "windows.audit.privilege_use.sensitive_privilege_use"),
            ("org.win.audit.pol_change", "Audit Policy Change", "high", "windows.audit.policy_change.audit_policy_change"),
            ("org.win.audit.sys_state", "Security State Change", "medium", "windows.audit.system.security_state_change"),
        )
    ],
]


# ============================================================================
# 2. CISCO IOS XE ROUTERS & SWITCHES
# ============================================================================
VTY = "line vty 0 15"
cisco_definitions = [
    # Management plane
    dict(id="org.cisco.mgmt.no_telnet", title="Ensure VTY lines accept SSH only (Telnet disabled)", severity="critical",
         fact="management.vty.telnet_permitted", op="eq", good=False, bad=True,
         why="Telnet transmits credentials and configuration in cleartext.", fix="Restrict VTY transport to SSH.",
         commands=["configure terminal", VTY, " transport input ssh", "end", "write memory"],
         verify="show running-config | section line vty"),
    dict(id="org.cisco.mgmt.ssh_v2", title="Ensure SSH version 2 is enforced", severity="high",
         fact="management.ssh.version_2_only", op="eq", good=True, bad=False,
         why="SSHv1 has known cryptographic weaknesses.", fix="Enforce SSH version 2.",
         commands=["configure terminal", "ip ssh version 2", "end", "write memory"], verify="show ip ssh"),
    dict(id="org.cisco.mgmt.ssh_timeout", title="Ensure SSH negotiation timeout is 60 seconds or less", severity="medium",
         fact="management.ssh.timeout_seconds", op="lte", good=60, bad=120,
         why="Long negotiation windows tie up sessions and aid brute force.", fix="Set the SSH timeout to 60 seconds.",
         commands=["configure terminal", "ip ssh time-out 60", "end", "write memory"], verify="show ip ssh"),
    dict(id="org.cisco.mgmt.ssh_retries", title="Ensure SSH authentication retries are 3 or fewer", severity="medium",
         fact="management.ssh.authentication_retries", op="lte", good=3, bad=5,
         why="Limits password guesses per connection.", fix="Allow at most 3 SSH authentication attempts.",
         commands=["configure terminal", "ip ssh authentication-retries 3", "end", "write memory"], verify="show ip ssh"),
    dict(id="org.cisco.mgmt.vty_timeout", title="Ensure VTY exec-timeout is 10 minutes or less", severity="high",
         fact="management.vty.max_exec_timeout_seconds", op="lte", good=600, bad=3600,
         why="Idle administrative sessions must close automatically.", fix="Set a 10-minute idle timeout on all VTY lines.",
         commands=["configure terminal", VTY, " exec-timeout 10 0", "end", "write memory"],
         verify="show running-config | section line vty"),
    dict(id="org.cisco.mgmt.vty_no_unlimited", title="Ensure no VTY line has an unlimited exec-timeout", severity="critical",
         fact="management.vty.unlimited_timeout_present", op="eq", good=False, bad=True,
         why="`exec-timeout 0 0` leaves privileged sessions open forever.", fix="Replace unlimited timeouts with 10 minutes.",
         commands=["configure terminal", VTY, " exec-timeout 10 0", "end", "write memory"],
         verify="show running-config | include exec-timeout"),
    dict(id="org.cisco.mgmt.vty_acl", title="Ensure an access-class restricts VTY access to management networks", severity="high",
         fact="management.vty.access_class_applied", op="eq", good=True, bad=False,
         why="Only management subnets should reach the device CLI.", fix="Apply a management ACL to all VTY lines.",
         commands=["configure terminal", "ip access-list standard MGMT-ONLY", " permit 10.20.100.0 0.0.0.255",
                   " deny any log", VTY, " access-class MGMT-ONLY in", "end", "write memory"],
         verify="show running-config | section line vty"),
    dict(id="org.cisco.mgmt.no_http", title="Ensure the HTTP management server is disabled", severity="critical",
         fact="management.http_server.enabled", op="eq", good=False, bad=True,
         why="HTTP management sends credentials in cleartext.", fix="Disable the HTTP server.",
         commands=["configure terminal", "no ip http server", "end", "write memory"],
         verify="show running-config | include ip http"),
    dict(id="org.cisco.mgmt.https_enabled", title="Ensure web management, if used, is HTTPS only", severity="medium",
         fact="management.https_server.enabled", op="eq", good=True, bad=False,
         why="Encrypted web management replaces cleartext HTTP.", fix="Enable the HTTPS server.",
         commands=["configure terminal", "ip http secure-server", "end", "write memory"],
         verify="show running-config | include ip http secure"),
    dict(id="org.cisco.aaa.new_model", title="Ensure AAA new-model is enabled", severity="high",
         fact="management.aaa.new_model", op="eq", good=True, bad=False,
         why="AAA centralises and logs administrator authentication.", fix="Enable AAA.",
         commands=["configure terminal", "aaa new-model", "aaa authentication login default local", "end", "write memory"],
         verify="show running-config | include aaa"),
    dict(id="org.cisco.mgmt.enable_secret", title="Ensure 'enable secret' is configured", severity="high",
         fact="management.enable_secret_configured", op="eq", good=True, bad=False,
         why="Privileged mode must be protected with a strongly hashed secret.", fix="Set an enable secret.",
         commands=["configure terminal", "enable algorithm-type scrypt secret <STRONG-SECRET>", "end", "write memory"],
         verify="show running-config | include enable secret"),
    dict(id="org.cisco.mgmt.pwd_encryption", title="Ensure 'service password-encryption' is enabled", severity="high",
         fact="management.console.password_encryption", op="eq", good=True, bad=False,
         why="Prevents cleartext passwords in configuration output.", fix="Enable password encryption.",
         commands=["configure terminal", "service password-encryption", "end", "write memory"],
         verify="show running-config | include password-encryption"),
    dict(id="org.cisco.log.banner", title="Ensure a login banner is configured", severity="low",
         fact="logging.banner.motd_present", op="eq", good=True, bad=False,
         why="A legal warning banner supports prosecution of misuse.", fix="Configure a MOTD banner.",
         commands=["configure terminal", "banner motd ^C Authorized access only. Activity is monitored. ^C", "end", "write memory"],
         verify="show banner motd"),
    # Logging & telemetry
    dict(id="org.cisco.snmp.no_v1v2c", title="Ensure no SNMPv1/v2c community strings are configured", severity="critical",
         fact="snmp.v1v2c_community_count", op="eq", good=0, bad=2,
         why="SNMPv1/v2c communities (e.g. public/private) are cleartext shared secrets.", fix="Remove all SNMP communities.",
         commands=["configure terminal", "no snmp-server community <COMMUNITY>", "end", "write memory"],
         verify="show running-config | include snmp-server community"),
    dict(id="org.cisco.snmp.v3_priv", title="Ensure SNMPv3 with authentication and privacy is used", severity="high",
         fact="snmp.v3_priv_configured", op="eq", good=True, bad=False,
         why="SNMPv3 authPriv encrypts and authenticates monitoring traffic.", fix="Configure an SNMPv3 authPriv group and user.",
         commands=["configure terminal", "snmp-server group MONITOR v3 priv",
                   "snmp-server user monitor MONITOR v3 auth sha <AUTH-KEY> priv aes 256 <PRIV-KEY>", "end", "write memory"],
         verify="show snmp group"),
    dict(id="org.cisco.log.syslog", title="Ensure syslog forwarding to a remote server is configured", severity="high",
         fact="logging.syslog.host_count", op="gte", good=1, bad=0, value=1,
         why="Remote logs survive device compromise and support investigation.", fix="Forward logs to the central syslog server.",
         commands=["configure terminal", "logging host 10.20.100.5", "logging trap informational", "end", "write memory"],
         verify="show logging | include Logging to"),
    dict(id="org.cisco.log.timestamps", title="Ensure log messages carry date-time timestamps", severity="medium",
         fact="logging.timestamps_enabled", op="eq", good=True, bad=False,
         why="Accurate timestamps are needed to correlate events.", fix="Enable datetime log timestamps.",
         commands=["configure terminal", "service timestamps log datetime msec localtime show-timezone", "end", "write memory"],
         verify="show running-config | include service timestamps"),
    dict(id="org.cisco.time.ntp", title="Ensure NTP time synchronization is configured", severity="high",
         fact="time.ntp.server_count", op="gte", good=1, bad=0, value=1,
         why="Consistent time is required for logs, certificates and forensics.", fix="Configure an NTP server.",
         commands=["configure terminal", "ntp server 10.20.100.1 prefer", "end", "write memory"],
         verify="show ntp associations"),
    dict(id="org.cisco.time.ntp_auth", title="Ensure NTP authentication is enabled", severity="medium",
         fact="time.ntp.authentication_enabled", op="eq", good=True, bad=False,
         why="Unauthenticated NTP can be spoofed to skew device time.", fix="Authenticate NTP sources.",
         commands=["configure terminal", "ntp authentication-key 1 hmac-sha2-256 <NTP-KEY>", "ntp trusted-key 1",
                   "ntp authenticate", "end", "write memory"],
         verify="show ntp status"),
    # ACLs
    dict(id="org.cisco.acl.no_permit_any_any", title="Ensure no ACL entry permits ip any any", severity="critical",
         fact="acl.permit_any_any_count", op="eq", good=0, bad=1,
         why="`permit ip any any` disables filtering for everything after it.", fix="Replace catch-all permits with explicit rules and a final deny.",
         commands=["configure terminal", "ip access-list extended <ACL-NAME>", " no permit ip any any",
                   " deny ip any any log", "end", "write memory"],
         verify="show access-lists"),
    dict(id="org.cisco.acl.no_sensitive_any", title="Ensure SSH/Telnet/SMB/RDP (22/23/445/3389) are not permitted from any source", severity="critical",
         fact="acl.sensitive_port_exposure_count", op="eq", good=0, bad=2,
         why="Management and file-sharing ports must only be reachable from trusted networks.",
         fix="Restrict sensitive ports to the management subnet.",
         commands=["configure terminal", "ip access-list extended <ACL-NAME>", " no permit tcp any any eq 22",
                   " permit tcp 10.20.100.0 0.0.0.255 any eq 22", "end", "write memory"],
         verify="show access-lists | include eq (22|23|445|3389)"),
    dict(id="org.cisco.acl.no_shadowed", title="Ensure no ACL entries are shadowed by earlier entries", severity="medium",
         fact="acl.shadowed_entry_count", op="eq", good=0, bad=3,
         why="Shadowed entries never match and hide the real effective policy.", fix="Remove or reorder unreachable ACL entries.",
         commands=["configure terminal", "ip access-list extended <ACL-NAME>", " no <SEQUENCE-OF-SHADOWED-ENTRY>",
                   "ip access-list resequence <ACL-NAME> 10 10", "end", "write memory"],
         verify="show access-lists <ACL-NAME>"),
    # Network hardening
    dict(id="org.cisco.net.no_source_route", title="Ensure IP source routing is disabled", severity="high",
         fact="management.ip.source_route_disabled", op="eq", good=True, bad=False,
         why="Source routing lets attackers choose packet paths around controls.", fix="Disable IP source routing.",
         commands=["configure terminal", "no ip source-route", "end", "write memory"],
         verify="show running-config | include source-route"),
    dict(id="org.cisco.net.no_cdp", title="Ensure CDP is disabled globally", severity="medium",
         fact="management.cdp.global_disabled", op="eq", good=True, bad=False,
         why="CDP leaks device model, version and addressing to neighbours.", fix="Disable CDP.",
         commands=["configure terminal", "no cdp run", "end", "write memory"], verify="show cdp"),
    # Switch hardening (switch role only)
    dict(id="org.cisco.switch.unused_ports_shutdown", title="Ensure unused switch ports are administratively shut down", severity="medium", role="switch",
         fact="switch.interfaces.unused_enabled_count", op="eq", good=0, bad=4,
         why="Live but unused ports let anyone plug in to the network.", fix="Shut down and park unused ports.",
         commands=["configure terminal", "interface range <UNUSED-PORTS>", " switchport access vlan 999", " shutdown",
                   "end", "write memory"],
         verify="show interfaces status | include notconnect"),
    dict(id="org.cisco.switch.port_security", title="Ensure Port Security is enabled on access ports", severity="high", role="switch",
         fact="switch.port_security.enabled", op="eq", good=True, bad=False,
         why="MAC binding limits rogue devices on access ports.", fix="Enable port security on access ports.",
         commands=["configure terminal", "interface range <ACCESS-PORTS>", " switchport mode access",
                   " switchport port-security", " switchport port-security maximum 2",
                   " switchport port-security violation restrict", "end", "write memory"],
         verify="show port-security"),
    dict(id="org.cisco.switch.dhcp_snooping", title="Ensure DHCP snooping is enabled", severity="high", role="switch",
         fact="switch.dhcp_snooping.enabled", op="eq", good=True, bad=False,
         why="Blocks rogue DHCP servers from redirecting clients.", fix="Enable DHCP snooping on user VLANs.",
         commands=["configure terminal", "ip dhcp snooping", "ip dhcp snooping vlan 10,20",
                   "interface <UPLINK>", " ip dhcp snooping trust", "end", "write memory"],
         verify="show ip dhcp snooping"),
    dict(id="org.cisco.switch.arp_inspection", title="Ensure Dynamic ARP Inspection is enabled", severity="high", role="switch",
         fact="switch.arp_inspection.enabled", op="eq", good=True, bad=False,
         why="Prevents ARP spoofing and man-in-the-middle attacks.", fix="Enable DAI on user VLANs.",
         commands=["configure terminal", "ip arp inspection vlan 10,20", "interface <UPLINK>",
                   " ip arp inspection trust", "end", "write memory"],
         verify="show ip arp inspection"),
    dict(id="org.cisco.switch.bpduguard", title="Ensure BPDU Guard is enabled by default on PortFast ports", severity="high", role="switch",
         fact="switch.spanning_tree.bpduguard_default", op="eq", good=True, bad=False,
         why="Stops rogue switches from joining the spanning tree.", fix="Enable BPDU Guard by default.",
         commands=["configure terminal", "spanning-tree portfast bpduguard default", "end", "write memory"],
         verify="show spanning-tree summary"),
    dict(id="org.cisco.switch.vlan1_no_mgmt", title="Ensure VLAN 1 does not carry management traffic", severity="high", role="switch",
         fact="switch.vlan1.management_ip_active", op="eq", good=False, bad=True,
         why="VLAN 1 is the default everywhere and is a common attack path.", fix="Move management to a dedicated VLAN and shut VLAN 1.",
         commands=["configure terminal", "interface Vlan99", " ip address 10.20.99.2 255.255.255.0", " no shutdown",
                   "interface Vlan1", " no ip address", " shutdown", "end", "write memory"],
         verify="show ip interface brief | include Vlan"),
    dict(id="org.cisco.switch.no_vlan1_access", title="Ensure no access ports are assigned to VLAN 1", severity="high", role="switch",
         fact="switch.interfaces.vlan_1_access_count", op="eq", good=0, bad=4,
         why="User ports in VLAN 1 share the default broadcast domain.", fix="Assign access ports to functional VLANs.",
         commands=["configure terminal", "interface range <PORTS-IN-VLAN1>", " switchport access vlan 10", "end", "write memory"],
         verify="show vlan brief"),
]


# ============================================================================
# 3. FORTINET FORTIGATE (FortiOS 7.x)
# ============================================================================
GLOBAL = "config system global"
forti_definitions = [
    dict(id="org.forti.mgmt.no_cleartext_admin", title="Ensure HTTP and Telnet administrative access are disabled on all interfaces", severity="critical",
         fact="fortigate.interface.cleartext_admin_access_count", op="eq", good=0, bad=2,
         why="HTTP/Telnet management exposes credentials in cleartext.", fix="Allow only HTTPS, SSH and ping on interfaces.",
         commands=["config system interface", "    edit <INTERFACE>", "        set allowaccess ping https ssh", "    next", "end"],
         verify="show system interface | grep -f allowaccess"),
    dict(id="org.forti.admin.https_redirect", title="Ensure HTTP administrative access redirects to HTTPS", severity="high",
         fact="fortigate.system.admin_https_redirect", op="eq", good=True, bad=False,
         why="Forces encrypted management sessions.", fix="Enable admin HTTPS redirect.",
         commands=[GLOBAL, "    set admin-https-redirect enable", "end"], verify="get system global | grep admin-https-redirect"),
    dict(id="org.forti.admin.strong_crypto", title="Ensure strong cryptography is enforced", severity="high",
         fact="fortigate.system.strong_crypto", op="eq", good=True, bad=False,
         why="Disables weak ciphers and protocols for management traffic.", fix="Enable strong-crypto.",
         commands=[GLOBAL, "    set strong-crypto enable", "end"], verify="get system global | grep strong-crypto"),
    dict(id="org.forti.admin.idle_timeout", title="Ensure administrator idle timeout is 15 minutes or less", severity="medium",
         fact="fortigate.system.admin_idle_timeout", op="lte", good=5, bad=30, value=15,
         why="Idle admin sessions must close automatically.", fix="Set admintimeout to 5 minutes.",
         commands=[GLOBAL, "    set admintimeout 5", "end"], verify="get system global | grep admintimeout"),
    dict(id="org.forti.admin.lockout_threshold", title="Ensure administrator lockout threshold is 3 or fewer attempts", severity="medium",
         fact="fortigate.system.admin_lockout_threshold", op="lte", good=3, bad=10, value=3,
         why="Throttles password guessing against admin accounts.", fix="Lock admins out after 3 failures.",
         commands=[GLOBAL, "    set admin-lockout-threshold 3", "end"], verify="get system global | grep admin-lockout"),
    dict(id="org.forti.admin.lockout_duration", title="Ensure administrator lockout duration is at least 900 seconds", severity="medium",
         fact="fortigate.system.admin_lockout_duration", op="gte", good=900, bad=60, value=900,
         why="A short lockout barely slows automated attacks.", fix="Lock admins out for 15 minutes.",
         commands=[GLOBAL, "    set admin-lockout-duration 900", "end"], verify="get system global | grep admin-lockout"),
    dict(id="org.forti.admin.password_policy", title="Ensure an administrator password policy is enabled", severity="high",
         fact="fortigate.password_policy.enabled", op="eq", good=True, bad=False,
         why="Enforces password strength for all administrators.", fix="Enable the password policy.",
         commands=["config system password-policy", "    set status enable", "    set minimum-length 12",
                   "    set min-upper-case-letter 1", "    set min-number 1", "    set min-non-alphanumeric 1", "end"],
         verify="show system password-policy"),
    dict(id="org.forti.admin.password_length", title="Ensure administrator passwords are at least 12 characters", severity="medium",
         fact="fortigate.password_policy.min_length", op="gte", good=12, bad=8, value=12,
         why="Longer passwords resist brute force.", fix="Require 12-character passwords.",
         commands=["config system password-policy", "    set minimum-length 12", "end"], verify="show system password-policy"),
    dict(id="org.forti.admin.pre_login_banner", title="Ensure a pre-login warning banner is enabled", severity="low",
         fact="fortigate.system.pre_login_banner", op="eq", good=True, bad=False,
         why="A legal notice is shown before administrators log in.", fix="Enable the pre-login banner.",
         commands=[GLOBAL, "    set pre-login-banner enable", "end"], verify="get system global | grep pre-login-banner"),
    dict(id="org.forti.admin.sport_custom", title="Ensure the admin HTTPS port is changed from 443", severity="low",
         fact="fortigate.system.admin_sport", op="ne", good=8443, bad=443, value=443,
         why="Reduces exposure to automated scanning of the management UI.", fix="Move admin HTTPS to a custom port.",
         commands=[GLOBAL, "    set admin-sport 8443", "end"], verify="get system global | grep admin-sport"),
    # Firewall policy
    dict(id="org.forti.fw.no_any_any_allow", title="Ensure no policy accepts all sources to all destinations for all services", severity="critical",
         fact="fortigate.firewall.any_any_allow_count", op="eq", good=0, bad=1,
         why="An any-any accept turns the firewall into a router.", fix="Replace any-any accepts with specific policies.",
         commands=["config firewall policy", "    edit <POLICY-ID>", '        set srcaddr "<SOURCE-GROUP>"',
                   '        set dstaddr "<DESTINATION-GROUP>"', '        set service "<SERVICES>"', "    next", "end"],
         verify="show firewall policy <POLICY-ID>"),
    dict(id="org.forti.fw.no_sensitive_from_any", title="Ensure SSH/RDP/SMB/Telnet are not accepted from any source", severity="critical",
         fact="fortigate.firewall.sensitive_service_exposure_count", op="eq", good=0, bad=2,
         why="Inbound 0.0.0.0/0 to 22/3389/445 is a primary intrusion vector.", fix="Restrict sensitive services to trusted sources.",
         commands=["config firewall policy", "    edit <POLICY-ID>", '        set srcaddr "MGMT-NET"', "    next", "end"],
         verify="show firewall policy <POLICY-ID>"),
    dict(id="org.forti.fw.no_shadowed", title="Ensure no firewall policies are shadowed by earlier policies", severity="medium",
         fact="fortigate.firewall.shadowed_policy_count", op="eq", good=0, bad=2,
         why="Shadowed policies never match and mislead reviewers.", fix="Reorder or delete shadowed policies.",
         commands=["config firewall policy", "    move <SHADOWED-ID> before <SHADOWING-ID>", "end"],
         verify="show firewall policy"),
    dict(id="org.forti.fw.default_deny", title="Ensure an explicit default-deny policy closes the rule base", severity="critical",
         fact="fortigate.firewall.has_default_deny", op="eq", good=True, bad=False,
         why="An explicit, logged final deny proves nothing else is allowed.", fix="Add a final deny-all policy with logging.",
         commands=["config firewall policy", "    edit 0", '        set name "DEFAULT-DENY"', '        set srcintf "any"',
                   '        set dstintf "any"', '        set srcaddr "all"', '        set dstaddr "all"',
                   '        set service "ALL"', "        set schedule always", "        set action deny",
                   "        set logtraffic all", "    next", "end"],
         verify='show firewall policy | grep -f "DEFAULT-DENY"'),
    dict(id="org.forti.fw.logging", title="Ensure all accept policies log all traffic", severity="medium",
         fact="fortigate.firewall.accept_without_logging_count", op="eq", good=0, bad=3,
         why="Session logs are needed to investigate incidents.", fix="Set logtraffic all on accept policies.",
         commands=["config firewall policy", "    edit <POLICY-ID>", "        set logtraffic all", "    next", "end"],
         verify="show firewall policy | grep -f logtraffic"),
    # Logging & telemetry
    dict(id="org.forti.log.syslog_enabled", title="Ensure remote syslog forwarding is enabled", severity="high",
         fact="fortigate.logging.syslog_status", op="eq", good=True, bad=False,
         why="Remote logs survive device compromise.", fix="Forward logs to the central syslog server.",
         commands=["config log syslogd setting", "    set status enable", '    set server "10.20.100.5"', "end"],
         verify="get log syslogd setting"),
    dict(id="org.forti.time.ntp", title="Ensure NTP time synchronization is enabled", severity="high",
         fact="fortigate.ntp.sync_enabled", op="eq", good=True, bad=False,
         why="Accurate time is required for logs and certificates.", fix="Enable NTP sync to a trusted server.",
         commands=["config system ntp", "    set ntpsync enable", "    set type custom", "    config ntpserver",
                   "        edit 1", '            set server "10.20.100.1"', "        next", "    end", "end"],
         verify="diagnose sys ntp status"),
    dict(id="org.forti.snmp.no_v1v2c", title="Ensure no SNMPv1/v2c communities are enabled", severity="high",
         fact="fortigate.snmp.v1v2c_community_count", op="eq", good=0, bad=1,
         why="Community strings are cleartext shared secrets.", fix="Delete SNMP v1/v2c communities.",
         commands=["config system snmp community", "    delete <COMMUNITY-ID>", "end"], verify="show system snmp community"),
    dict(id="org.forti.snmp.v3_priv", title="Ensure SNMPv3 with authentication and privacy is configured", severity="high",
         fact="fortigate.snmp.v3_priv_configured", op="eq", good=True, bad=False,
         why="SNMPv3 authPriv encrypts monitoring traffic.", fix="Create an SNMPv3 authPriv user.",
         commands=["config system snmp user", '    edit "monitor"', "        set security-level auth-priv",
                   "        set auth-proto sha256", "        set auth-pwd <AUTH-KEY>", "        set priv-proto aes256",
                   "        set priv-pwd <PRIV-KEY>", "    next", "end"],
         verify="show system snmp user"),
    dict(id="org.forti.admin.ssh_port_custom", title="Ensure the admin SSH port is changed from 22", severity="low",
         fact="fortigate.system.admin_ssh_port", op="ne", good=2222, bad=22, value=22,
         why="Reduces automated SSH scanning noise against the firewall.", fix="Move admin SSH to a custom port.",
         commands=[GLOBAL, "    set admin-ssh-port 2222", "end"], verify="get system global | grep admin-ssh-port"),
]


def build_pack(*, pack_id, title_family, families, version_range, roles, definitions, prefix, platform, authority):
    controls, templates = [], {}
    for index, d in enumerate(definitions, 1):
        d = {**d, "rem_id": f"manual.{prefix}.{index:02d}"}
        controls.append(create_control(d, families=families, platform=platform))
        templates[d["rem_id"]] = remediation(d, authority=authority)
    ids = [c["id"] for c in controls]
    assert len(ids) == len(set(ids)), f"duplicate control ids in {pack_id}"
    facts = [c["assertion"]["fact"] for c in controls]
    assert len(facts) == len(set(facts)), f"two controls assert the same fact in {pack_id}"
    pack = {
        "schema_version": "1.0",
        "pack_id": pack_id,
        "version": PACK_VERSION,
        "publisher": "BaselineGuard project",
        "license": "Apache-2.0",
        "rights_reference": "Original project-authored organizational baseline. No benchmark text included.",
        "engine_compatibility": ">=0.1.0 <2.0.0",
        "benchmark": None,
        "targets": {"family": title_family, "version_range": version_range, "roles": roles},
        "parameters": {},
        "controls": controls,
    }
    return pack, templates


win_pack, win_rem = build_pack(
    pack_id="org.baselineguard.windows.server2019", title_family="windows_server", families=["windows_server", "windows"],
    version_range=">=2019", roles=["standalone", "member_server", "domain_controller", "workstation"],
    definitions=win_definitions, prefix="win", platform="Windows Server 2019/2022 and Windows 11",
    authority="Domain Group Policy (GPO) if the setting is centrally managed; otherwise Local Security Policy.",
)
cisco_pack, cisco_rem = build_pack(
    pack_id="org.baselineguard.cisco.iosxe", title_family="cisco_ios_xe", families=["cisco_ios_xe"],
    version_range=">=16.9 <=17.15", roles=["router", "switch"], definitions=cisco_definitions, prefix="cisco",
    platform="Cisco IOS XE routers and switches", authority="Device running-config, or the network controller (e.g. DNA Center) if it owns the template.",
)
forti_pack, forti_rem = build_pack(
    pack_id="org.baselineguard.fortinet.fortigate", title_family="fortigate", families=["fortigate"],
    version_range=">=7.0 <=7.6", roles=["appliance_root_vdom", "firewall"], definitions=forti_definitions, prefix="forti",
    platform="FortiGate firewalls", authority="Local FortiOS configuration, or FortiManager if the device is centrally managed.",
)


def main():
    ORIGINAL.mkdir(parents=True, exist_ok=True)
    REMEDIATION.mkdir(parents=True, exist_ok=True)
    for pack_file, pdata, rem_file, templates in (
        ("windows-server-2019.yaml", win_pack, "windows-server-2019.json", win_rem),
        ("cisco-iosxe-hardening.yaml", cisco_pack, "cisco-iosxe-hardening.json", cisco_rem),
        ("fortigate-fortios.yaml", forti_pack, "fortigate-fortios.json", forti_rem),
    ):
        jsonschema.validate(instance=pdata, schema=schema)
        (ORIGINAL / pack_file).write_text(json.dumps(pdata, indent=2), encoding="utf-8")
        print(f"Validated and wrote {pack_file} ({len(pdata['controls'])} controls)")
        payload = {
            "schema_version": "1.0",
            "note": "Original project-authored remediation guidance. Review before use; BaselineGuard never executes these commands.",
            "templates": templates,
        }
        (REMEDIATION / rem_file).write_text(json.dumps(payload, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
