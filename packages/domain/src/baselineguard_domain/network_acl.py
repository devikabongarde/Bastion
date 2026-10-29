"""Bounded exact analysis for static first-match IPv4/IPv6 L3/L4 rules.

This module intentionally does not infer routing, NAT, schedules, identity policy,
or Internet reachability. Its witness means a modeled policy match, not a packet.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import Literal

AddressNetwork = IPv4Network | IPv6Network
Interval = tuple[int, int]
Box = tuple[Interval, Interval, Interval, Interval, Interval, Interval]
Protocol = Literal["any", "tcp", "udp", "icmp", "icmpv6"]
_PROTOCOL_NUMBERS: dict[str, tuple[int, int]] = {
    "tcp": (6, 6),
    "udp": (17, 17),
    "icmp": (1, 1),
    "icmpv6": (58, 58),
    "any": (0, 255),
}
_ALL_PORTS: tuple[Interval, ...] = ((0, 65535),)
_SENSITIVE_TCP_PORTS = (22, 3389, 445)


@dataclass(frozen=True, slots=True)
class ACLRule:
    rule_id: str
    sequence: int
    context_id: str
    action: Literal["permit", "deny"]
    sources: tuple[str, ...]
    destinations: tuple[str, ...]
    protocols: tuple[Protocol, ...] = ("any",)
    source_ports: tuple[Interval, ...] = _ALL_PORTS
    destination_ports: tuple[Interval, ...] = _ALL_PORTS
    enabled: bool = True
    terminating: bool = True
    attached: bool = True
    complete: bool = True
    schedule: Literal["always", "conditional", "unknown"] = "always"


@dataclass(frozen=True, slots=True)
class ShadowFinding:
    rule_id: str
    sequence: int
    classification: Literal["fully_shadowed", "partially_shadowed"]
    shadowing_rule_ids: tuple[str, ...]
    shadowing_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BroadAllowWitness:
    rule_id: str
    context_id: str
    family: Literal[4, 6]
    protocol: Literal["tcp"]
    source: str
    destination: str
    destination_port: int
    evaluated_rule_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ACLAnalysis:
    status: Literal["PROVEN", "UNKNOWN"]
    reason_code: str | None
    shadows: tuple[ShadowFinding, ...]
    broad_allows: tuple[BroadAllowWitness, ...]
    unattached_rule_ids: tuple[str, ...]
    analyzed_rule_count: int


class AnalysisLimitExceeded(Exception):
    """Exact analysis exceeded its deterministic work budget."""


class _Budget:
    def __init__(self, max_fragments: int) -> None:
        if not 1 <= max_fragments <= 100_000:
            raise ValueError("max_fragments must be between 1 and 100000")
        self.remaining = max_fragments

    def charge(self, count: int) -> None:
        self.remaining -= count
        if self.remaining < 0:
            raise AnalysisLimitExceeded


def _validated_ports(intervals: tuple[Interval, ...]) -> tuple[Interval, ...]:
    if not intervals:
        raise ValueError("port sets must not be empty")
    if len(intervals) > 1024:
        raise ValueError("port-set alternatives exceed the static analyzer bound")
    ordered = tuple(sorted(intervals))
    if any(start < 0 or end > 65535 or start > end for start, end in ordered):
        raise ValueError("ports must be inclusive intervals from 0 through 65535")
    if any(left[1] >= right[0] for left, right in zip(ordered, ordered[1:], strict=False)):
        raise ValueError("port intervals must be disjoint and non-adjacent")
    return ordered


def _rule_boxes(rule: ACLRule, budget: _Budget) -> tuple[Box, ...]:
    if not rule.rule_id or len(rule.rule_id) > 200 or not rule.context_id:
        raise ValueError("rule and context identifiers are required")
    if rule.sequence < 0:
        raise ValueError("rule sequence must be non-negative")
    if not rule.sources or not rule.destinations or not rule.protocols:
        raise ValueError("static address and protocol sets must be non-empty")
    if max(len(rule.sources), len(rule.destinations), len(rule.protocols)) > 1024:
        raise AnalysisLimitExceeded
    source_ports = _validated_ports(rule.source_ports)
    destination_ports = _validated_ports(rule.destination_ports)
    protocols: set[int] = set()
    for protocol in rule.protocols:
        bounds = _PROTOCOL_NUMBERS.get(protocol)
        if bounds is None:
            raise ValueError("unsupported protocol")
        protocols.update(range(bounds[0], bounds[1] + 1))
    if (protocols - {6, 17}) and (source_ports != _ALL_PORTS or destination_ports != _ALL_PORTS):
        raise ValueError("transport ports are only modeled for TCP/UDP rules")

    sources = tuple(ip_network(value, strict=True) for value in rule.sources)
    destinations = tuple(ip_network(value, strict=True) for value in rule.destinations)
    boxes: list[Box] = []
    for source in sources:
        for destination in destinations:
            if source.version != destination.version:
                continue
            for protocol in sorted(protocols):
                for source_port in source_ports:
                    for destination_port in destination_ports:
                        budget.charge(1)
                        boxes.append(
                            (
                                (protocol, protocol),
                                (source.version, source.version),
                                (int(source.network_address), int(source.broadcast_address)),
                                (
                                    int(destination.network_address),
                                    int(destination.broadcast_address),
                                ),
                                source_port,
                                destination_port,
                            )
                        )
    return tuple(boxes)


def _intersection(left: Box, right: Box) -> Box | None:
    axes: list[Interval] = []
    for (left_low, left_high), (right_low, right_high) in zip(left, right, strict=True):
        low, high = max(left_low, right_low), min(left_high, right_high)
        if low > high:
            return None
        axes.append((low, high))
    return tuple(axes)  # type: ignore[return-value]


def _subtract(box: Box, cover: Box, budget: _Budget) -> tuple[Box, ...]:
    """Return pairwise-disjoint fragments of box minus cover."""
    overlap = _intersection(box, cover)
    if overlap is None:
        return (box,)
    remaining = list(box)
    fragments: list[Box] = []
    for axis, (overlap_low, overlap_high) in enumerate(overlap):
        budget.charge(1)
        low, high = remaining[axis]
        if low < overlap_low:
            slab = list(remaining)
            slab[axis] = (low, overlap_low - 1)
            fragments.append(tuple(slab))  # type: ignore[arg-type]
            remaining[axis] = (overlap_low, high)
        low, high = remaining[axis]
        if overlap_high < high:
            slab = list(remaining)
            slab[axis] = (overlap_high + 1, high)
            fragments.append(tuple(slab))  # type: ignore[arg-type]
            remaining[axis] = (low, overlap_high)
    budget.charge(len(fragments) + 1)
    return tuple(fragments)


def _subtract_all(
    boxes: tuple[Box, ...], covers: tuple[Box, ...], budget: _Budget
) -> tuple[Box, ...]:
    remaining = list(boxes)
    for cover in covers:
        next_remaining: list[Box] = []
        for box in remaining:
            next_remaining.extend(_subtract(box, cover, budget))
        remaining = next_remaining
        if not remaining:
            break
    return tuple(remaining)


def _int_to_ip(value: int, family: int) -> str:
    return str(IPv4Address(value) if family == 4 else IPv6Address(value))


def analyze_acl(
    rules: tuple[ACLRule, ...], *, max_rules: int = 5000, max_fragments: int = 100_000
) -> ACLAnalysis:
    """Analyze attached, always-active static L3/L4 rules in ordered context.

    Unsupported/incomplete context or budget exhaustion returns UNKNOWN and no
    partial exact findings. Unattached policies are surfaced separately.
    """
    if not 1 <= max_rules <= 5000 or not 1 <= len(rules) <= max_rules:
        return ACLAnalysis("UNKNOWN", "ANALYSIS_LIMIT", (), (), (), len(rules))
    budget = _Budget(max_fragments)
    if any(
        not rule.complete or rule.schedule != "always"
        for rule in rules
        if rule.attached and rule.enabled
    ):
        return ACLAnalysis("UNKNOWN", "UNSUPPORTED_OR_INCOMPLETE_CONTEXT", (), (), (), len(rules))
    attached = tuple(
        sorted(
            (r for r in rules if r.attached and r.enabled),
            key=lambda r: (r.context_id, r.sequence, r.rule_id),
        )
    )
    unattached = tuple(sorted(r.rule_id for r in rules if not r.attached and r.enabled))
    if len({(rule.context_id, rule.sequence) for rule in attached}) != len(attached):
        raise ValueError("rule sequence must be unique within a context")
    try:
        parsed = {rule.rule_id: _rule_boxes(rule, budget) for rule in attached}
        shadows: list[ShadowFinding] = []
        broad: list[BroadAllowWitness] = []
        prior_by_context: dict[str, list[ACLRule]] = {}
        for rule in attached:
            prior = prior_by_context.setdefault(rule.context_id, [])
            boxes = parsed[rule.rule_id]
            if not boxes:
                raise ValueError("rule source and destination address families do not intersect")
            if rule.terminating and prior and boxes:
                remaining: list[Box] = []
                for box in boxes:
                    remaining.extend(
                        _subtract_all(
                            (box,),
                            tuple(cover for earlier in prior for cover in parsed[earlier.rule_id]),
                            budget,
                        )
                    )
                if not remaining:
                    shadows.append(
                        ShadowFinding(
                            rule_id=rule.rule_id,
                            sequence=rule.sequence,
                            classification="fully_shadowed",
                            shadowing_rule_ids=tuple(r.rule_id for r in prior),
                            shadowing_actions=tuple(r.action for r in prior),
                        )
                    )
                elif sum(_volume(item) for item in remaining) != sum(
                    _volume(item) for item in boxes
                ):
                    shadows.append(
                        ShadowFinding(
                            rule_id=rule.rule_id,
                            sequence=rule.sequence,
                            classification="partially_shadowed",
                            shadowing_rule_ids=tuple(r.rule_id for r in prior),
                            shadowing_actions=tuple(r.action for r in prior),
                        )
                    )
            if rule.terminating and rule.action == "permit" and rule.protocols == ("tcp",):
                seen_families: set[int] = set()
                broad_sources = [
                    ip_network(source, strict=True)
                    for source in rule.sources
                    if ip_network(source, strict=True).prefixlen == 0
                ]
                if broad_sources:
                    for box in boxes:
                        (
                            protocol,
                            family_range,
                            source,
                            destination,
                            source_port,
                            destination_port,
                        ) = box
                        family = family_range[0]
                        if protocol != (6, 6) or source_port[0] != 0:
                            continue
                        max_address = (1 << (32 if family == 4 else 128)) - 1
                        if source != (0, max_address):
                            continue
                        if family in seen_families:
                            continue
                        sensitive = next(
                            (
                                port
                                for port in _SENSITIVE_TCP_PORTS
                                if destination_port[0] <= port <= destination_port[1]
                            ),
                            None,
                        )
                        if sensitive is None:
                            continue
                        blockers = tuple(
                            cover for earlier in prior for cover in parsed[earlier.rule_id]
                        )
                        witness_box = _subtract_all((box,), blockers, budget)
                        if not witness_box:
                            continue
                        witness = min(witness_box, key=lambda item: tuple(axis[0] for axis in item))
                        broad.append(
                            BroadAllowWitness(
                                rule_id=rule.rule_id,
                                context_id=rule.context_id,
                                family=family,  # type: ignore[arg-type]
                                protocol="tcp",
                                source=_int_to_ip(witness[2][0], family),
                                destination=_int_to_ip(witness[3][0], family),
                                destination_port=sensitive,
                                evaluated_rule_ids=tuple(r.rule_id for r in (*prior, rule)),
                            )
                        )
                        seen_families.add(family)
            if rule.terminating:
                prior.append(rule)
    except AnalysisLimitExceeded:
        return ACLAnalysis("UNKNOWN", "ANALYSIS_LIMIT", (), (), unattached, len(attached))
    return ACLAnalysis("PROVEN", None, tuple(shadows), tuple(broad), unattached, len(attached))


def _volume(box: Box) -> int:
    result = 1
    for low, high in box:
        result *= high - low + 1
    return result
