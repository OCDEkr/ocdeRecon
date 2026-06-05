"""Scope enforcement (PROJECT.md §10).

A hard guardrail for authorized testing: targets outside the engagement's scope
are never scanned. This module only *classifies* targets (pure, UI-free); callers
decide the consequence — manual runs block with a logged override, workflow steps
skip-and-log (even when unattended).

Rules and targets may be IPs, CIDR ranges, or hostnames. IP/CIDR targets are
checked with the stdlib ``ipaddress`` module (a target network must sit entirely
within an include range and not overlap any exclude). Hostnames are matched by
exact string (no DNS resolution — that would itself touch the network).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from pentui.core.models import ScopeKind, ScopeRule

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeStatus(StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    NO_RULES = "no_rules"  # the engagement has no scope defined


@dataclass(slots=True)
class ScopeDecision:
    target: str
    status: ScopeStatus
    reason: str

    @property
    def blocked(self) -> bool:
        return self.status is ScopeStatus.OUT_OF_SCOPE


def _as_network(value: str) -> Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _subnet_of(a: Network, b: Network) -> bool:
    if isinstance(a, ipaddress.IPv4Network) and isinstance(b, ipaddress.IPv4Network):
        return a.subnet_of(b)
    if isinstance(a, ipaddress.IPv6Network) and isinstance(b, ipaddress.IPv6Network):
        return a.subnet_of(b)
    return False


def _overlaps(a: Network, b: Network) -> bool:
    if isinstance(a, ipaddress.IPv4Network) and isinstance(b, ipaddress.IPv4Network):
        return a.overlaps(b)
    if isinstance(a, ipaddress.IPv6Network) and isinstance(b, ipaddress.IPv6Network):
        return a.overlaps(b)
    return False


class ScopeChecker:
    """Classifies targets against a project's include/exclude rules."""

    def __init__(self, rules: Iterable[ScopeRule]) -> None:
        self.include_nets: list[Network] = []
        self.exclude_nets: list[Network] = []
        self.include_hosts: set[str] = set()
        self.exclude_hosts: set[str] = set()
        self._has_rules = False
        for rule in rules:
            self._has_rules = True
            net = _as_network(rule.value)
            if rule.kind is ScopeKind.INCLUDE:
                self.include_nets.append(net) if net else self.include_hosts.add(rule.value)
            else:
                self.exclude_nets.append(net) if net else self.exclude_hosts.add(rule.value)

    @property
    def has_rules(self) -> bool:
        return self._has_rules

    def classify(self, target: str) -> ScopeDecision:
        if not self._has_rules:
            return ScopeDecision(target, ScopeStatus.NO_RULES, "no scope rules defined")
        net = _as_network(target)
        if net is not None:
            return self._classify_network(target, net)
        return self._classify_host(target)

    def _classify_network(self, target: str, net: Network) -> ScopeDecision:
        for ex in self.exclude_nets:
            if _overlaps(net, ex):
                return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, f"overlaps exclude {ex}")
        for inc in self.include_nets:
            if _subnet_of(net, inc):
                return ScopeDecision(target, ScopeStatus.IN_SCOPE, f"within include {inc}")
        return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, "not within any include range")

    def _classify_host(self, target: str) -> ScopeDecision:
        if target in self.exclude_hosts:
            return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, "matches an exclude rule")
        if target in self.include_hosts:
            return ScopeDecision(target, ScopeStatus.IN_SCOPE, "matches an include rule")
        return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, "hostname not in scope")


def classify_targets(rules: Iterable[ScopeRule], targets: Iterable[str]) -> list[ScopeDecision]:
    checker = ScopeChecker(rules)
    return [checker.classify(t) for t in targets]
