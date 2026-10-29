import json

from baselineguard_adapters.normalize import (
    parse_windows_auditpol,
    parse_windows_firewall,
    parse_windows_os_version,
    parse_windows_registry_json,
    parse_windows_secedit,
    parse_windows_services,
)
from baselineguard_contracts.common import FactState


def test_parse_windows_os_version() -> None:
    data = json.dumps({
        "Caption": "Microsoft Windows Server 2019 Datacenter",
        "Version": "10.0.17763",
        "BuildNumber": "17763",
        "ProductType": 3,
    })
    facts = {f["key"]: f for f in parse_windows_os_version(data)}
    assert facts["platform.family"]["value"] == "windows_server"
    assert facts["platform.family"]["state"] == FactState.PRESENT.value
    assert facts["platform.role"]["value"] == "member_server"
    assert "17763" in facts["platform.build"]["value"]


def test_parse_windows_registry_json() -> None:
    data = json.dumps({
        "LimitBlankPasswordUse": 1,
        "SMB1": 0,
        "EnableAdminApprovalMode": 1,
        "ConsentPromptBehaviorAdmin": 2,
        "PromptOnSecureDesktop": 1,
        "UserRemoteLogonRestriction": 1,
        "fPromptForPassword": 1,
        "UserAuthentication": 1,
        "ScreenSaverIsSecure": 1,
        "ScreenSaveTimeOut": 900,
    })
    facts = {f["key"]: f for f in parse_windows_registry_json(data)}
    assert facts["windows.registry.lsa.limit_blank_password_use"]["value"] == 1
    assert facts["windows.registry.smbv1_disabled"]["value"] is True
    assert facts["windows.registry.uac.admin_approval_mode"]["value"] == 1
    assert facts["windows.registry.rdp.require_nla"]["value"] == 1
    assert facts["windows.registry.screensaver.timeout_seconds"]["value"] == 900


def test_parse_windows_secedit() -> None:
    secedit_text = """
    [System Access]
    MinimumPasswordLength = 14
    PasswordComplexity = 1
    MaximumPasswordAge = 60
    MinimumPasswordAge = 1
    PasswordHistorySize = 24
    LockoutBadCount = 5
    LockoutDuration = 15
    ResetLockoutCount = 15
    """
    facts = {f["key"]: f for f in parse_windows_secedit(secedit_text)}
    assert facts["windows.security_policy.password.min_length"]["value"] == 14
    assert facts["windows.security_policy.password.complexity"]["value"] == 1
    assert facts["windows.security_policy.password.max_age_days"]["value"] == 60
    assert facts["windows.security_policy.lockout.threshold"]["value"] == 5


def test_parse_windows_auditpol() -> None:
    audit_text = """
    Machine Name,Subcategory,Inclusion Setting,Exclusion Setting
    WIN-SRV,Logon,Success and Failure,No Auditing
    WIN-SRV,User Account Management,Success and Failure,No Auditing
    WIN-SRV,Sensitive Privilege Use,Success and Failure,No Auditing
    WIN-SRV,Audit Policy Change,Success and Failure,No Auditing
    WIN-SRV,Security State Change,Success and Failure,No Auditing
    """
    facts = {f["key"]: f for f in parse_windows_auditpol(audit_text)}
    assert facts["windows.audit.logon_logoff.logon"]["value"] == "Success and Failure"
    assert facts["windows.audit.account_management.user_account_management"]["value"] == "Success and Failure"


def test_parse_windows_firewall() -> None:
    data = json.dumps([
        {"Name": "Domain", "Enabled": True, "DefaultInboundAction": "Block"},
        {"Name": "Private", "Enabled": True, "DefaultInboundAction": "Block"},
        {"Name": "Public", "Enabled": True, "DefaultInboundAction": "Block"},
    ])
    facts = {f["key"]: f for f in parse_windows_firewall(data)}
    assert facts["windows.firewall.domain.enabled"]["value"] is True
    assert facts["windows.firewall.domain.default_inbound_block"]["value"] is True
    assert facts["windows.firewall.public.enabled"]["value"] is True


def test_parse_windows_services() -> None:
    data = json.dumps([
        {"Name": "Telnet", "Status": "Stopped", "StartType": "Disabled"},
        {"Name": "RemoteRegistry", "Status": "Stopped", "StartType": "Disabled"},
        {"Name": "SSDPSRV", "Status": "Stopped", "StartType": "Disabled"},
    ])
    facts = {f["key"]: f for f in parse_windows_services(data)}
    assert facts["windows.services.telnet.disabled"]["value"] is True
    assert facts["windows.services.remote_registry.disabled"]["value"] is True
