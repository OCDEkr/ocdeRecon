"""Scope enforcement (PROJECT.md §10).

A hard guardrail for authorized testing: targets outside the engagement's scope
are never scanned. This module only *classifies* targets (pure, UI-free); callers
decide the consequence — manual runs block with a logged override, workflow steps
skip-and-log (even when unattended).

Rules and targets may be IPs, CIDR ranges, arbitrary IP ranges, or hostnames.
Numeric values are normalized to a canonical ``(start, end)`` integer range via
``parse_range`` — this accepts single IPs, CIDR (``10.0.0.0/24``), full begin-end
ranges (``10.0.5.17-10.3.200.4``, masscan style) and last-octet shorthand
(``192.168.1.10-20``, nmap style), so scoping and the exclude file no longer
depend on a syntax both tools happen to share. A target range must sit entirely
within an include range and not sit entirely within an exclude. A target that
*contains* a smaller excluded range stays in scope — it's an in-scope range with
a carve-out hole, honored at scan time via ``--excludefile`` and by filtering the
individual hosts it yields — so one excluded ``/32`` never voids a whole ``/16``.
The exclude file is rendered as CIDR blocks (``summarize_address_range``), the one
syntax every IP scanner accepts, so a single engagement-wide file stays valid for
both nmap and masscan. Hostnames match a rule
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
from typing import NamedTuple

from pentui.core.models import ScopeKind, ScopeRule

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class IPRange(NamedTuple):
    """A canonical, inclusive IP range. ``label`` is the text it was parsed from
    (used in scope-decision reasons); ``version`` keeps IPv4/IPv6 from mixing."""

    version: int
    start: int
    end: int
    label: str

    def contains(self, other: IPRange) -> bool:
        """True if ``other`` sits wholly inside this range (same IP version)."""
        return self.version == other.version and self.start <= other.start and other.end <= self.end


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


def parse_range(value: str) -> IPRange | None:
    """Canonicalize a numeric scope value to an inclusive ``IPRange``.

    Accepts a single IP, CIDR, a full begin-end range (``10.0.5.17-10.3.200.4``,
    masscan style) or last-octet shorthand (``192.168.1.10-20``, nmap style).
    Returns ``None`` when ``value`` is not numeric (a hostname) or is malformed,
    so callers route it through hostname matching instead.
    """
    text = value.strip()
    if "-" in text:  # IPv6 literals never contain '-', so this is a range form
        lo, _, hi = text.partition("-")
        lo, hi = lo.strip(), hi.strip()
        try:
            start = ipaddress.ip_address(lo)
        except ValueError:
            return None
        # Last-group shorthand: "192.168.1.10-20" -> hi becomes "192.168.1.20".
        if start.version == 4 and "." not in hi:
            hi = ".".join(lo.split(".")[:-1] + [hi])
        elif start.version == 6 and ":" not in hi:
            hi = ":".join(lo.split(":")[:-1] + [hi])
        try:
            end = ipaddress.ip_address(hi)
        except ValueError:
            return None
        if end.version != start.version or int(end) < int(start):
            return None
        return IPRange(start.version, int(start), int(end), value)
    net = _as_network(text)
    if net is None:
        return None
    return IPRange(net.version, int(net.network_address), int(net.broadcast_address), value)


class ScopeChecker:
    """Classifies targets against a project's include/exclude rules."""

    def __init__(self, rules: Iterable[ScopeRule]) -> None:
        self.include_ranges: list[IPRange] = []
        self.exclude_ranges: list[IPRange] = []
        self.include_hosts: set[str] = set()
        self.exclude_hosts: set[str] = set()
        self._has_rules = False
        for rule in rules:
            self._has_rules = True
            rng = parse_range(rule.value)
            if rule.kind is ScopeKind.INCLUDE:
                self.include_ranges.append(rng) if rng else self.include_hosts.add(rule.value)
            else:
                self.exclude_ranges.append(rng) if rng else self.exclude_hosts.add(rule.value)

    @property
    def has_rules(self) -> bool:
        return self._has_rules

    def classify(self, target: str) -> ScopeDecision:
        if not self._has_rules:
            return ScopeDecision(target, ScopeStatus.NO_RULES, "no scope rules defined")
        rng = parse_range(target)
        if rng is not None:
            return self._classify_range(target, rng)
        return self._classify_host(target)

    def _classify_range(self, target: str, rng: IPRange) -> ScopeDecision:
        # Block only when the target sits *wholly inside* an exclude — a target that
        # merely *contains* (or partially overlaps) an excluded range, e.g. a /16
        # with one excluded /32, is an in-scope range with a carve-out hole, not an
        # out-of-scope target. The hole is honored at scan time: nmap/masscan get the
        # excluded ranges via --excludefile, and downstream tools operate on
        # discovered hosts, which are individually filtered here. Blocking the whole
        # range would (wrongly) skip everything.
        for ex in self.exclude_ranges:
            if ex.contains(rng):
                return ScopeDecision(target, ScopeStatus.OUT_OF_SCOPE, f"within exclude {ex.label}")
        for inc in self.include_ranges:
            if inc.contains(rng):
                return ScopeDecision(target, ScopeStatus.IN_SCOPE, f"within include {inc.label}")
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
    """Write the engagement's exclude rules (one entry per line) to ``path``.

    Returns ``path`` when at least one exclude rule exists (file written), else
    ``None`` (no file created). The result feeds tools that accept an
    ``--excludefile`` — the second line of defence behind ``classify_targets``,
    needed because a per-/24 fan-out scans a whole in-scope CIDR and would
    otherwise sweep excluded IPs sitting inside it.

    Numeric excludes are rendered as CIDR blocks (a single IP stays bare) — the
    one syntax both nmap and masscan accept — so an arbitrary range like
    ``10.0.5.17-10.3.200.4`` becomes a minimal set of CIDRs valid for either
    tool. Non-numeric excludes (hostnames) are passed through verbatim.
    """
    lines: list[str] = []
    for rule in rules:
        if rule.kind is not ScopeKind.EXCLUDE:
            continue
        rng = parse_range(rule.value)
        if rng is None:
            lines.append(rule.value)  # hostname — nmap resolves it, masscan ignores
            continue
        addr = ipaddress.IPv4Address if rng.version == 4 else ipaddress.IPv6Address
        if rng.start == rng.end:
            lines.append(str(addr(rng.start)))
        else:
            cidrs = ipaddress.summarize_address_range(addr(rng.start), addr(rng.end))
            lines += [str(c) for c in cidrs]
    if not lines:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    return path
