# Adapter compatibility and verification

This file interprets the machine-readable [`content/compatibility.yaml`](../../content/compatibility.yaml) conservatively. A component's existence, a successful unit test, or a command transcript fixture does not demonstrate live platform compatibility. Only record a live row as verified after authorized collection on the exact product/version/role and permission profile, with captured negative cases and documented reviewer/date.

## Current evidence

| Family | Code present | Fixture/unit evidence | Authorized live evidence | Claim allowed |
|---|---|---|---|---|
| Ubuntu 22.04 Linux over SSH | Fixed command reader and transport | Unit tests for scope, host-key behavior and parsing/evaluation | Not available in this workspace | Development implementation only |
| Cisco IOS XE router | Fixed `show` reader and secret redaction | No end-to-end device contract evidence sufficient for support | Not available | Experimental reader component |
| Cisco IOS XE switch | Fixed `show` reader; interface/VLAN command set | No live feature/firmware evidence | Not available | Experimental reader component |
| Windows 11 / Server 2019 | No reader | None | Not available | Unsupported |
| RHEL 8/9; Ubuntu 20.04 | No production reader | None | Not available | Unsupported |
| FortiGate | No reader | ACL library tests are not a FortiGate adapter test | Not available | Unsupported |
| Cisco ASA, PAN-OS, Check Point, Sophos | No readers | None | Not available | Unsupported |

## Reader safety contract

1. Resolve a target only inside the explicitly configured site scope; pin the authorized address for the connection to avoid DNS rebinding.
2. Use encrypted management transport and pinned/managed host identity. Unknown or changed host keys fail closed. No Telnet fallback or trust-on-first-use.
3. Reader commands are fixed in reviewed code. Do not interpolate user strings into a remote shell or expose a generic command endpoint.
4. Record timeout, byte bounds, exit/authorization errors, reader identity and source hash. Missing or malformed output produces unavailable/unknown/error evidence, never a pass.
5. Redact secret-bearing material before persisting or exporting evidence. Keep enough provenance to show that redaction occurred.
6. Distinguish session-local terminal display commands from configuration changes. No target configuration write command is permitted.
7. Test expected, missing, permission-denied, localized, malformed, maximum-size, timeout, host-key mismatch, and unsupported-version behavior for each claimed profile.

## Promotion checklist

An adapter can be moved from experimental to supported only after the corresponding PRD gate has: an authorized representative lab; frozen product/build/role/management-plane matrix; least-privilege account evidence; complete normalized evidence contract; control-by-control fixtures; held-out accuracy results; redaction/security review; measured collection resource limits; reviewer approval; and updated compatibility manifest. If any required field is unavailable, publish that limitation explicitly rather than widening the support claim.
