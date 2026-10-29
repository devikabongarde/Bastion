from baselineguard_adapters.normalize import (
    parse_fortios_firewall_policy,
    parse_fortios_status,
    parse_fortios_syslog,
    parse_fortios_system_global,
)


def test_parse_fortios_status() -> None:
    status_text = """
    Version: FortiGate-VM64 v7.4.3,build2573,240207 (GA.F)
    Virus-DB: 1.00000(2020-10-19 02:47)
    Extended DB: 1.00000(2020-10-19 02:47)
    IPS-DB: 6.00741(2015-12-01 02:30)
    FortiOS Release: 7.4.3
    Hostname: FG-EDGE-01
    Virtual domain configuration: enable
    """
    facts = {f["key"]: f for f in parse_fortios_status(status_text)}
    assert facts["platform.family"]["value"] == "fortigate"
    assert facts["platform.version"]["value"] == "7.4.3"
    assert facts["fortigate.system.hostname"]["value"] == "FG-EDGE-01"
    assert facts["fortigate.system.vdom_mode"]["value"] == "multi"


def test_parse_fortios_system_global() -> None:
    global_text = """
    set admin-https-redirect enable
    set pre-login-banner enable
    set strong-crypto enable
    set admin-sport 8443
    set admin-ssh-port 2222
    set admintimeout 10
    """
    facts = {f["key"]: f for f in parse_fortios_system_global(global_text)}
    assert facts["fortigate.system.admin_https_redirect"]["value"] is True
    assert facts["fortigate.system.pre_login_banner"]["value"] is True
    assert facts["fortigate.system.strong_crypto"]["value"] is True
    assert facts["fortigate.system.admin_sport"]["value"] == 8443
    assert facts["fortigate.system.admin_ssh_port"]["value"] == 2222
    assert facts["fortigate.system.admin_idle_timeout"]["value"] == 10


def test_parse_fortios_firewall_policy() -> None:
    policy_text = """
    config firewall policy
        edit 1
            set name "LAN-to-WAN"
            set srcintf "internal"
            set dstintf "wan1"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set schedule "always"
            set service "all"
            set logtraffic all
        next
        edit 2
            set name "DMZ-to-Internal"
            set srcintf "dmz"
            set dstintf "internal"
            set srcaddr "DMZ_Subnet"
            set dstaddr "App_Server"
            set action accept
            set service "HTTPS"
            set logtraffic all
        next
    end
    """
    facts = {f["key"]: f for f in parse_fortios_firewall_policy(policy_text)}
    assert facts["fortigate.firewall.any_any_allow_count"]["value"] == 1
    assert facts["fortigate.firewall.total_policies"]["value"] == 2
    assert facts["fortigate.firewall.logtraffic_all_count"]["value"] == 2
    assert facts["fortigate.firewall.has_default_deny"]["value"] is True


def test_parse_fortios_syslog() -> None:
    syslog_text = """
    set status enable
    set server "10.20.100.5"
    set mode udp
    set port 514
    """
    facts = {f["key"]: f for f in parse_fortios_syslog(syslog_text)}
    assert facts["fortigate.logging.syslog_status"]["value"] is True
    assert facts["fortigate.logging.syslog_server"]["value"] == "10.20.100.5"
