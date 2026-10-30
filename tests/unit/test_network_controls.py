"""Fact extraction for the CIS-style network controls (Cisco IOS XE, FortiGate, Windows)."""

from baselineguard_adapters.cisco_iosxe.reader import redact_cisco_config
from baselineguard_adapters.normalize import (
    analyze_cisco_acls,
    parse_cisco_interfaces_status,
    parse_fortios_firewall_policy,
    parse_fortios_interfaces,
    parse_fortios_snmp_community,
    parse_fortios_system_global,
    parse_running_config,
    parse_windows_services,
)


def facts(items):
    return {item["key"]: item["value"] for item in items}


def test_vty_ranges_with_two_numbers_are_parsed():
    config = "line vty 0 4\n exec-timeout 10 0\n transport input ssh\nline vty 5 15\n exec-timeout 30 0\n"
    parsed = facts(parse_running_config(config))
    assert parsed["management.vty.max_exec_timeout_seconds"] == 1800
    # vty 5 15 has no explicit transport, so Telnet is not ruled out
    assert parsed["management.vty.telnet_permitted"] is True


def test_ssh_only_vty_with_access_class_passes():
    config = "line vty 0 15\n access-class MGMT in\n exec-timeout 5 0\n transport input ssh\n"
    parsed = facts(parse_running_config(config))
    assert parsed["management.vty.telnet_permitted"] is False
    assert parsed["management.vty.access_class_applied"] is True


def test_ios_defaults_apply_when_ssh_settings_absent():
    parsed = facts(parse_running_config("ip ssh version 2\n"))
    assert parsed["management.ssh.timeout_seconds"] == 120
    assert parsed["management.ssh.authentication_retries"] == 3


def test_acl_any_any_sensitive_and_shadowed_entries():
    lines = [
        "ip access-list extended edge-in",
        "10 permit tcp 10.20.100.0 0.0.0.255 any eq 22",
        "20 permit tcp any any eq 3389",
        "30 permit tcp any host 10.20.5.10 eq 443",
        "40 permit tcp any host 10.20.5.10 eq 443",
        "50 permit ip any any",
        "60 permit tcp any any eq 445",
        "!",
        "access-list 101 permit ip any any",
    ]
    result = analyze_cisco_acls(lines)
    assert result["permit_any_any"] == 2
    assert result["sensitive_exposure"] == 2  # 3389 and 445 from any
    # 40 duplicates 30; 60 is covered by the earlier `permit ip any any`
    assert result["shadowed"] == 2


def test_acl_restricted_to_trusted_source_is_clean():
    lines = ["ip access-list extended mgmt", "10 permit tcp 10.0.0.0 0.0.0.255 any eq 22", "20 deny ip any any log"]
    assert analyze_cisco_acls(lines) == {"permit_any_any": 0, "sensitive_exposure": 0, "shadowed": 0}


def test_switch_hardening_facts():
    config = (
        "ip dhcp snooping\nip dhcp snooping vlan 10\nip arp inspection vlan 10\n"
        "snmp-server community <redacted> RO\nsnmp-server group MON v3 priv\n"
        "interface Vlan1\n no ip address\n shutdown\n!\n"
    )
    parsed = facts(parse_running_config(config))
    assert parsed["switch.dhcp_snooping.enabled"] is True
    assert parsed["switch.arp_inspection.enabled"] is True
    assert parsed["switch.vlan1.management_ip_active"] is False
    assert parsed["snmp.v1v2c_community_count"] == 1
    assert parsed["snmp.v3_priv_configured"] is True


def test_vlan1_with_ip_is_management_traffic():
    parsed = facts(parse_running_config("interface Vlan1\n ip address 10.0.1.2 255.255.255.0\n!\n"))
    assert parsed["switch.vlan1.management_ip_active"] is True


def test_unused_ports_count_only_notconnect():
    text = (
        "Port Name Status Vlan Duplex Speed Type\n"
        "Gi1/0/1 pc connected 10 a-full a-1000 x\n"
        "Gi1/0/2    notconnect 1 auto auto x\n"
        "Gi1/0/3    disabled 999 auto auto x\n"
    )
    assert facts(parse_cisco_interfaces_status(text))["switch.interfaces.unused_enabled_count"] == 1


def test_redaction_keeps_command_but_drops_secret():
    redacted = redact_cisco_config("enable secret 9 $9$abc\nsnmp-server community s3cret RO 10\nhostname x")
    assert "enable secret <redacted>" in redacted
    assert "snmp-server community <redacted> RO 10" in redacted
    assert "s3cret" not in redacted and "$9$abc" not in redacted


POLICY = """config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "WEB"
        set action accept
        set service "HTTPS"
        set logtraffic all
    next
    edit 2
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "WEB"
        set action accept
        set service "HTTPS"
    next
    edit 3
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 4
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "TS"
        set action accept
        set service "RDP"
        set status disable
    next
end
"""


def test_fortigate_policy_analysis():
    parsed = facts(parse_fortios_firewall_policy(POLICY))
    assert parsed["fortigate.firewall.any_any_allow_count"] == 1
    assert parsed["fortigate.firewall.shadowed_policy_count"] == 1
    assert parsed["fortigate.firewall.accept_without_logging_count"] == 2
    # Disabled policies are ignored, and there is no closing deny-all
    assert parsed["fortigate.firewall.sensitive_service_exposure_count"] == 0
    assert parsed["fortigate.firewall.has_default_deny"] is False


def test_fortigate_explicit_default_deny_detected():
    text = POLICY.replace(
        "end\n",
        '    edit 9\n        set srcaddr "all"\n        set dstaddr "all"\n        set service "ALL"\n'
        "        set action deny\n    next\nend\n",
    )
    assert facts(parse_fortios_firewall_policy(text))["fortigate.firewall.has_default_deny"] is True


def test_fortigate_padded_get_output_is_understood():
    parsed = facts(parse_fortios_system_global("strong-crypto      : enable\nadmintimeout       : 30\n"))
    assert parsed["fortigate.system.strong_crypto"] is True
    assert parsed["fortigate.system.admin_idle_timeout"] == 30


def test_fortigate_cleartext_admin_and_snmp():
    interfaces = "name: wan1   allowaccess: ping https http   type: physical\nname: lan   allowaccess: ping ssh   type: x\n"
    assert facts(parse_fortios_interfaces(interfaces))["fortigate.interface.cleartext_admin_access_count"] == 1
    community = "config system snmp community\n    edit 1\n    next\n    edit 2\n        set status disable\n    next\nend\n"
    assert facts(parse_fortios_snmp_community(community))["fortigate.snmp.v1v2c_community_count"] == 1


def test_unparseable_windows_services_are_unknown_not_pass():
    items = parse_windows_services("not json")
    assert all(item["state"] == "UNAVAILABLE" for item in items)


def test_auditpol_without_privilege_is_unknown_not_fail():
    from baselineguard_adapters.normalize import parse_windows_auditpol

    assert all(item["state"] == "UNAVAILABLE" for item in parse_windows_auditpol(""))


def test_windows_firewall_numeric_enums():
    from baselineguard_adapters.normalize import parse_windows_firewall

    text = (
        '[{"Name":"Domain","Enabled":1,"DefaultInboundAction":0},'
        '{"Name":"Private","Enabled":1,"DefaultInboundAction":4},'
        '{"Name":"Public","Enabled":0,"DefaultInboundAction":2}]'
    )
    parsed = facts(parse_windows_firewall(text))
    assert parsed["windows.firewall.domain.default_inbound_block"] is True  # NotConfigured -> default Block
    assert parsed["windows.firewall.private.default_inbound_block"] is True
    assert parsed["windows.firewall.public.default_inbound_block"] is False  # explicit Allow
    assert parsed["windows.firewall.public.enabled"] is False


def test_windows_registry_documented_defaults():
    from baselineguard_adapters.normalize import parse_windows_registry_json

    parsed = facts(parse_windows_registry_json('{"EnableAdminApprovalMode": null, "fPromptForPassword": null}'))
    assert parsed["windows.registry.uac.admin_approval_mode"] == 1  # Windows default: on
    assert parsed["windows.registry.rdp.prompt_for_password"] == 0  # unset policy: not enforced
