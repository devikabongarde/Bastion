"""Adapter orchestration: reader output -> normalized, typed fact snapshot.

The same normalization path serves live SSH collection and declared offline
fixture/output bundles, so evaluation semantics cannot diverge between modes.
"""

from __future__ import annotations

from typing import Any, TypedDict

from baselineguard_contracts.common import FactState, NormalizedFact

from baselineguard_adapters.linux.ssh import LINUX_READERS, ReadOutput
from baselineguard_adapters.normalize import (
    ParseLimitExceeded,  # noqa: F401  (re-exported for callers)
    fact,
    parse_cisco_interfaces_status,
    parse_cisco_port_security,
    parse_cisco_spanning_tree,
    parse_cisco_switchport,
    parse_file_modes,
    parse_fortios_firewall_policy,
    parse_fortios_interfaces,
    parse_fortios_ntp,
    parse_fortios_password_policy,
    parse_fortios_snmp_community,
    parse_fortios_snmp_user,
    parse_fortios_status,
    parse_fortios_syslog,
    parse_fortios_system_global,
    parse_os_release,
    parse_running_config,
    parse_service_active,
    parse_show_version,
    parse_sshd_effective,
    parse_sysctl_multi,
    parse_timedatectl,
    parse_umask_defaults,
    parse_windows_auditpol,
    parse_windows_firewall,
    parse_windows_os_version,
    parse_windows_registry_json,
    parse_windows_secedit,
    parse_windows_services,
)

REDACTION_VERSION = "v1"


class RawAdapterResult(TypedDict):
    adapter_id: str
    reader_outputs: tuple[ReadOutput, ...]
    error: str | None  # stable error code, when collection failed


def _pointer(reader_id: str, output: ReadOutput) -> dict[str, Any]:
    return {
        "artifact_sha256": output.source_sha256,
        "reader_id": reader_id,
        "pointer": {"lines": [1, max(1, output.text.count("\n") + 1)]},
        "redaction_version": REDACTION_VERSION,
    }


def _add(
    facts: dict[str, NormalizedFact],
    items: list[dict[str, Any]],
    output: ReadOutput,
) -> None:
    pointer = _pointer(output.reader_id, output)
    for item in items:
        key = item["key"]
        state = FactState(item["state"])
        existing = facts.get(key)
        if existing is not None and existing.state is FactState.PRESENT:
            # Observed evidence wins over the absence marker of a second parser.
            continue
        facts[key] = NormalizedFact.model_validate(
            {
                "fact_id": key,
                "state": state.value,
                "value": item["value"],
                "source": pointer,
            }
        )


def normalize_outputs(results: list[tuple[str, ReadOutput]]) -> list[NormalizedFact]:
    """Convert reader outputs of every shipped adapter into NormalizedFacts."""
    outputs = {reader_id: output for reader_id, output in results}
    facts: dict[str, NormalizedFact] = {}

    os_release = outputs.get("linux.identity.os_release")
    if os_release is not None:
        family, version = parse_os_release(os_release.text)
        _add(facts, [family, version], os_release)

    sshd = outputs.get("linux.ssh.effective_config")
    if sshd is not None:
        _add(facts, parse_sshd_effective(sshd.text), sshd)

    sysctl = outputs.get("linux.kernel.security_sysctl")
    if sysctl is not None:
        # Values are positional: if any key failed, the rest no longer line up, so trust
        # the output only when every key was read.
        _add(
            facts,
            parse_sysctl_multi(
                LINUX_READERS["linux.kernel.security_sysctl"],
                sysctl.text if sysctl.exit_code == 0 else "",
            ),
            sysctl,
        )

    modes = outputs.get("linux.files.security_modes")
    if modes is not None:
        _add(facts, parse_file_modes(modes.text), modes)

    umask = outputs.get("linux.auth.umask_defaults")
    if umask is not None:
        _add(facts, parse_umask_defaults(umask.text), umask)

    ntp = outputs.get("linux.time.ntp_state")
    if ntp is not None:
        _add(facts, parse_timedatectl(ntp.text), ntp)

    auditd = outputs.get("linux.auditd.active")
    if auditd is not None:
        _add(facts, parse_service_active(auditd.text, "services.auditd.active"), auditd)

    show_version = outputs.get("iosxe.identity.show_version")
    if show_version is not None:
        _add(facts, parse_show_version(show_version.text), show_version)

    running_config = outputs.get("iosxe.config.running")
    if running_config is not None:
        _add(facts, parse_running_config(running_config.text), running_config)

    # Cisco IOS XE Switch
    switchport = outputs.get("iosxe.switch.interfaces_switchport")
    if switchport is not None:
        _add(facts, parse_cisco_switchport(switchport.text), switchport)

    spanning_tree = outputs.get("iosxe.switch.spanning_tree")
    if spanning_tree is not None:
        _add(facts, parse_cisco_spanning_tree(spanning_tree.text), spanning_tree)

    port_security = outputs.get("iosxe.switch.port_security")
    if port_security is not None:
        _add(facts, parse_cisco_port_security(port_security.text), port_security)

    interfaces_status = outputs.get("iosxe.switch.interfaces_status")
    if interfaces_status is not None:
        _add(facts, parse_cisco_interfaces_status(interfaces_status.text), interfaces_status)

    if show_version is not None:
        # The reader set reveals the device role: switch readers run only on switches.
        role = "switch" if switchport is not None else "router"
        _add(facts, [fact("platform.role", role, FactState.PRESENT)], show_version)

    # Windows (Server 2019 / Windows 11)
    win_os = outputs.get("windows.identity.os_version")
    if win_os is not None:
        _add(facts, parse_windows_os_version(win_os.text), win_os)

    win_reg = outputs.get("windows.registry.security_settings")
    if win_reg is not None:
        _add(facts, parse_windows_registry_json(win_reg.text), win_reg)

    win_sec = outputs.get("windows.security_policy.secedit")
    if win_sec is not None:
        _add(facts, parse_windows_secedit(win_sec.text), win_sec)

    win_audit = outputs.get("windows.audit.auditpol")
    if win_audit is not None:
        _add(facts, parse_windows_auditpol(win_audit.text), win_audit)

    win_fw = outputs.get("windows.firewall.profiles")
    if win_fw is not None:
        _add(facts, parse_windows_firewall(win_fw.text), win_fw)

    win_svc = outputs.get("windows.services.state")
    if win_svc is not None:
        _add(facts, parse_windows_services(win_svc.text), win_svc)

    # Fortinet FortiOS
    fg_status = outputs.get("fortigate.identity.status")
    if fg_status is not None:
        _add(facts, parse_fortios_status(fg_status.text), fg_status)

    fg_global = outputs.get("fortigate.system.global")
    if fg_global is not None:
        _add(facts, parse_fortios_system_global(fg_global.text), fg_global)

    fg_policy = outputs.get("fortigate.firewall.policy")
    if fg_policy is not None:
        _add(facts, parse_fortios_firewall_policy(fg_policy.text), fg_policy)

    fg_syslog = outputs.get("fortigate.log.syslog")
    if fg_syslog is not None:
        _add(facts, parse_fortios_syslog(fg_syslog.text), fg_syslog)

    for reader_id, parser in (
        ("fortigate.system.interface", parse_fortios_interfaces),
        ("fortigate.system.ntp", parse_fortios_ntp),
        ("fortigate.snmp.community", parse_fortios_snmp_community),
        ("fortigate.snmp.user", parse_fortios_snmp_user),
        ("fortigate.system.password_policy", parse_fortios_password_policy),
    ):
        output = outputs.get(reader_id)
        if output is not None:
            _add(facts, parser(output.text), output)

    return list(facts.values())
