from baselineguard_adapters.normalize import (
    parse_cisco_port_security,
    parse_cisco_spanning_tree,
    parse_cisco_switchport,
)


def test_parse_cisco_switchport() -> None:
    text = """
    Name: Gi1/0/1
    Operational Mode: static access
    Access Mode VLAN: 1 (default)
    !
    Name: Gi1/0/2
    Operational Mode: static access
    Access Mode VLAN: 10 (Users)
    !
    Name: Gi1/0/24
    Operational Mode: trunk
    """
    facts = {f["key"]: f for f in parse_cisco_switchport(text)}
    assert facts["switch.interfaces.access_count"]["value"] == 2
    assert facts["switch.interfaces.trunk_count"]["value"] == 1
    assert facts["switch.interfaces.vlan_1_access_count"]["value"] == 1


def test_parse_cisco_spanning_tree() -> None:
    text = """
    Switch is in rapid-pvst mode
    Root bridge for: none
    PortFast BPDU Guard is enabled
    """
    facts = {f["key"]: f for f in parse_cisco_spanning_tree(text)}
    assert facts["switch.spanning_tree.bpduguard_default"]["value"] is True
    assert "rapid-pvst" in facts["switch.spanning_tree.mode"]["value"]


def test_parse_cisco_port_security() -> None:
    text = """
    Port Security              : Enabled
    Port_Succesful_logins      : 10
    """
    facts = {f["key"]: f for f in parse_cisco_port_security(text)}
    assert facts["switch.port_security.enabled"]["value"] is True

