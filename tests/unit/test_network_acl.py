from dataclasses import replace

from baselineguard_domain.network_acl import ACLRule, analyze_acl


def rule(
    rule_id: str,
    sequence: int,
    *,
    action: str = "deny",
    sources: tuple[str, ...] = ("10.0.0.0/24",),
    destinations: tuple[str, ...] = ("192.0.2.1/32",),
    destination_ports: tuple[tuple[int, int], ...] = ((443, 443),),
    protocols: tuple[str, ...] = ("tcp",),
    terminating: bool = True,
    context_id: str = "inside-to-app",
) -> ACLRule:
    return ACLRule(
        rule_id=rule_id,
        sequence=sequence,
        context_id=context_id,
        action=action,  # type: ignore[arg-type]
        sources=sources,
        destinations=destinations,
        protocols=protocols,  # type: ignore[arg-type]
        destination_ports=destination_ports,
        terminating=terminating,
    )


def test_full_shadow_uses_union_of_preceding_rules_and_reports_conflicting_action() -> None:
    result = analyze_acl(
        (
            rule("deny-first-half", 10, sources=("10.0.0.0/25",)),
            rule("deny-second-half", 20, sources=("10.0.0.128/25",)),
            rule("later-permit", 30, action="permit"),
        )
    )
    assert result.status == "PROVEN"
    assert len(result.shadows) == 1
    assert result.shadows[0].rule_id == "later-permit"
    assert result.shadows[0].classification == "fully_shadowed"
    assert result.shadows[0].shadowing_rule_ids == ("deny-first-half", "deny-second-half")
    assert result.shadows[0].shadowing_actions == ("deny", "deny")


def test_partial_shadow_and_context_boundaries_are_preserved() -> None:
    result = analyze_acl(
        (
            rule("prior-half", 10, sources=("10.0.0.0/25",)),
            rule("partially-covered", 20, action="permit", sources=("10.0.0.0/24",)),
            rule("other-context", 10, action="permit", context_id="dmz-to-app"),
        )
    )
    assert [(finding.rule_id, finding.classification) for finding in result.shadows] == [
        ("partially-covered", "partially_shadowed")
    ]


def test_broad_source_sensitive_port_emits_deterministic_ipv4_and_ipv6_witnesses() -> None:
    result = analyze_acl(
        (
            rule(
                "broad-admin",
                10,
                action="permit",
                sources=("0.0.0.0/0", "::/0"),
                destinations=("0.0.0.0/0", "::/0"),
                destination_ports=((22, 22), (3389, 3389)),
            ),
        )
    )
    assert [
        (finding.family, finding.source, finding.destination, finding.destination_port)
        for finding in result.broad_allows
    ] == [
        (4, "0.0.0.0", "0.0.0.0", 22),  # noqa: S104
        (6, "::", "::", 22),
    ]


def test_preceding_deny_blocks_broad_witness_but_nonterminating_rule_does_not() -> None:
    broad = rule(
        "broad-admin",
        20,
        action="permit",
        sources=("0.0.0.0/0",),
        destinations=("192.0.2.1/32",),
        destination_ports=((22, 22),),
    )
    blocked = analyze_acl(
        (
            rule(
                "deny-all-admin",
                10,
                sources=("0.0.0.0/0",),
                destinations=("192.0.2.1/32",),
                destination_ports=((22, 22),),
            ),
            broad,
        )
    )
    assert blocked.broad_allows == ()

    logged = analyze_acl((rule("log", 10, terminating=False), broad))
    assert len(logged.broad_allows) == 1


def test_incomplete_input_or_fragment_limit_never_returns_a_clean_exact_result() -> None:
    incomplete = replace(rule("incomplete", 10), complete=False)
    assert analyze_acl((incomplete,)).reason_code == "UNSUPPORTED_OR_INCOMPLETE_CONTEXT"

    limit_result = analyze_acl(
        (
            rule("prior-half", 10, sources=("10.0.0.0/25",)),
            rule("wide", 20, action="permit", sources=("10.0.0.0/24",)),
        ),
        max_fragments=1,
    )
    assert limit_result.reason_code == "ANALYSIS_LIMIT"
    assert limit_result.shadows == ()
    assert limit_result.broad_allows == ()
