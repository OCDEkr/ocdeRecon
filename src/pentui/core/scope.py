"""Scope enforcement (PROJECT.md §10).

A hard guardrail for authorized testing: targets outside the engagement's scope
are never scanned. This module only *classifies* targets (pure, UI-free); callers
decide the consequence — manual runs block with a logged override, workflow steps
skip-and-log (even when unattended).

Rules and targets may be IPs, CIDR ranges, or hostnames. IP/CIDR targets are
checked with the stdlib ``ipaddress`` module (a target network must sit entirely
within an include range and not sit entirely within an exclude). A target that
*contains* a smaller excluded range stays in scope — it's an in-scope range with
a carve-out hole, honored at scan time via ``--excludefile`` and by filtering the
individual hosts it yields — so one excluded ``/32`` never voids a whole ``/16``.
Hostnames match a rule
exactly OR as a subdomain of it — an include/exclude of ``example.com`` covers
``www.example.com`` (but not ``notexample.com``). This lets domain scoping work
with dynamically discovered subdomains (e.g. sublist3r). No DNS resolution is
done — that would itself touch the network.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

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
        # Two IP networks are always either disjoint or nested. Block only when the
        # target sits *wholly inside* an exclude — a target that merely *contains*
        # an excluded subnet (e.g. a /16 with one excluded /32) is an in-scope range
        # with a carve-out hole, not an out-of-scope target. The hole is honored at
        # scan time: nmap/masscan get the excluded ranges via --excludefile, and
        # downstream tools operate on discovered hosts, which are individually
        # filtered here. Blocking the whole range would (wrongly) skip everything.
        for ex in self.exclude_nets:
            if _subnet_of(net, ex):
                return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, f"within exclude {ex}")
        for inc in self.include_nets:
            if _subnet_of(net, inc):
                return ScopeDecision(target, ScopeStatus.IN_SCOPE, f"within include {inc}")
        return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, "not within any include range")

    def _classify_host(self, target: str) -> ScopeDecision:
        if self._host_in(target, self.exclude_hosts):
            return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, "matches an exclude rule")
        if self._host_in(target, self.include_hosts):
            return ScopeDecision(target, ScopeStatus.IN_SCOPE, "matches an include rule")
        return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, "hostname not in scope")

    @staticmethod
    def _host_in(target: str, rules: set[str]) -> bool:
        """True if ``target`` equals a rule or is a subdomain of one.

        ``example.com`` matches ``example.com`` and ``www.example.com`` but not
        ``notexample.com`` (the boundary must fall on a dotted label).
        """
        host = target.rstrip(".").lower()
        for rule in rules:
            r = rule.rstrip(".").lower()
            if host == r or host.endswith("." + r):
                return True
        return False


def classify_targets(rules: Iterable[ScopeRule], targets: Iterable[str]) -> list[ScopeDecision]:
    checker = ScopeChecker(rules)
    return [checker.classify(t) for t in targets]


def write_exclude_file(rules: Iterable[ScopeRule], path: Path) -> Path | None:
    """Write the engagement's exclude rules (one value per line) to ``path``.

    Returns ``path`` when at least one exclude rule exists (file written), else
    ``None`` (no file created). The result feeds tools that accept an
    ``--excludefile`` — the second line of defence behind ``classify_targets``,
    needed because a per-/24 fan-out scans a whole in-scope CIDR and would
    otherwise sweep excluded IPs sitting inside it.
    """
    excludes = [r.value for r in rules if r.kind is ScopeKind.EXCLUDE]
    if not excludes:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(excludes) + "\n")
    return path
