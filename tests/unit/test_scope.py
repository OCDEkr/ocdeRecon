"""Scope classification tests."""

from __future__ import annotations

import pytest

from pentui.core.models import ScopeKind, ScopeRule
from pentui.core.scope import (
    ScopeChecker,
    ScopeStatus,
    classify_targets,
    parse_range,
    write_exclude_file,
)


def _rules(*pairs: tuple[str, ScopeKind]) -> list[ScopeRule]:
    return [ScopeRule(project_id=1, value=v, kind=k) for v, k in pairs]


def test_no_rules_is_no_rules_status():
    decision = ScopeChecker([]).classify("10.0.0.1")
    assert decision.status is ScopeStatus.NO_RULES
    assert not decision.blocked


def test_ip_within_include_is_in_scope():
    checker = ScopeChecker(_rules(("10.0.0.0/24", ScopeKind.INCLUDE)))
    assert checker.classify("10.0.0.5").status is ScopeStatus.IN_SCOPE
    assert checker.classify("10.0.1.5").status is ScopeStatus.OUT_OF_SCOPE


def test_cidr_target_must_be_subnet_of_include():
    checker = ScopeChecker(_rules(("10.0.0.0/24", ScopeKind.INCLUDE)))
    assert checker.classify("10.0.0.0/25").status is ScopeStatus.IN_SCOPE
    # A broader range than the include is not fully in scope.
    assert checker.classify("10.0.0.0/23").status is ScopeStatus.OUT_OF_SCOPE


def test_exclude_overrides_include():
    checker = ScopeChecker(
        _rules(("10.0.0.0/24", ScopeKind.INCLUDE), ("10.0.0.13", ScopeKind.EXCLUDE))
    )
    assert checker.classify("10.0.0.5").status is ScopeStatus.IN_SCOPE
    blocked = checker.classify("10.0.0.13")
    assert blocked.status is ScopeStatus.OUT_OF_SCOPE
    assert "exclude" in blocked.reason


def test_range_containing_an_excluded_ip_stays_in_scope():
    # A single excluded /32 must not void the whole including range — the range is
    # scanned with the excluded IP carved out at scan time, not skipped outright.
    checker = ScopeChecker(
        _rules(("192.168.0.0/16", ScopeKind.INCLUDE), ("192.168.15.114", ScopeKind.EXCLUDE))
    )
    assert checker.classify("192.168.0.0/16").status is ScopeStatus.IN_SCOPE
    assert checker.classify("192.168.15.0/24").status is ScopeStatus.IN_SCOPE
    # …while the excluded address itself, and any range wholly inside the exclude,
    # are still out of scope.
    assert checker.classify("192.168.15.114").status is ScopeStatus.OUT_OF_SCOPE


def test_range_wholly_inside_an_exclude_is_blocked():
    checker = ScopeChecker(
        _rules(("10.0.0.0/8", ScopeKind.INCLUDE), ("10.1.0.0/16", ScopeKind.EXCLUDE))
    )
    # A /24 entirely within the excluded /16 is blocked …
    assert checker.classify("10.1.2.0/24").status is ScopeStatus.OUT_OF_SCOPE
    # … but a sibling /16 that only borders it is fine.
    assert checker.classify("10.2.0.0/16").status is ScopeStatus.IN_SCOPE


def test_hostname_scope_by_exact_match():
    checker = ScopeChecker(
        _rules(("app.example", ScopeKind.INCLUDE), ("admin.example", ScopeKind.EXCLUDE))
    )
    assert checker.classify("app.example").status is ScopeStatus.IN_SCOPE
    assert checker.classify("admin.example").status is ScopeStatus.OUT_OF_SCOPE
    assert checker.classify("other.example").status is ScopeStatus.OUT_OF_SCOPE


def test_hostname_scope_covers_subdomains():
    # A domain include/exclude covers its subdomains, but not lookalikes.
    checker = ScopeChecker(
        _rules(("example.com", ScopeKind.INCLUDE), ("secret.example.com", ScopeKind.EXCLUDE))
    )
    assert checker.classify("example.com").status is ScopeStatus.IN_SCOPE
    assert checker.classify("www.example.com").status is ScopeStatus.IN_SCOPE
    assert checker.classify("a.b.example.com").status is ScopeStatus.IN_SCOPE
    # excluded subdomain (and its children) win over the broader include
    assert checker.classify("secret.example.com").status is ScopeStatus.OUT_OF_SCOPE
    assert checker.classify("db.secret.example.com").status is ScopeStatus.OUT_OF_SCOPE
    # a lookalike domain is NOT a subdomain
    assert checker.classify("notexample.com").status is ScopeStatus.OUT_OF_SCOPE
    assert checker.classify("example.com.evil.net").status is ScopeStatus.OUT_OF_SCOPE


def test_mixed_ip_versions_do_not_crash():
    checker = ScopeChecker(_rules(("10.0.0.0/24", ScopeKind.INCLUDE)))
    # An IPv6 target against an IPv4-only include is simply out of scope.
    assert checker.classify("2001:db8::1").status is ScopeStatus.OUT_OF_SCOPE


@pytest.mark.parametrize("public", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_ips_blocked_for_private_scope(public):
    checker = ScopeChecker(_rules(("10.0.0.0/8", ScopeKind.INCLUDE)))
    assert checker.classify(public).blocked


def test_classify_targets_helper():
    decisions = classify_targets(
        _rules(("10.0.0.0/24", ScopeKind.INCLUDE)),
        ["10.0.0.1", "8.8.8.8"],
    )
    blocked = [d.target for d in decisions if d.blocked]
    assert blocked == ["8.8.8.8"]


def test_write_exclude_file_writes_only_exclude_values(tmp_path):
    rules = _rules(
        ("10.0.0.0/24", ScopeKind.INCLUDE),
        ("10.0.0.50", ScopeKind.EXCLUDE),
        ("10.0.0.99", ScopeKind.EXCLUDE),
    )
    path = tmp_path / "sub" / "excludes.txt"
    result = write_exclude_file(rules, path)
    assert result == path
    assert path.read_text().split() == ["10.0.0.50", "10.0.0.99"]


def test_write_exclude_file_returns_none_without_excludes(tmp_path):
    rules = _rules(("10.0.0.0/24", ScopeKind.INCLUDE))
    path = tmp_path / "excludes.txt"
    assert write_exclude_file(rules, path) is None
    assert not path.exists()


# --- IP range support (masscan/nmap syntaxes normalized to one canonical form) ---


@pytest.mark.parametrize(
    "value,version,start,end",
    [
        ("10.0.0.5", 4, "10.0.0.5", "10.0.0.5"),
        ("10.0.0.0/24", 4, "10.0.0.0", "10.0.0.255"),
        ("10.0.5.17-10.3.200.4", 4, "10.0.5.17", "10.3.200.4"),  # full begin-end
        ("192.168.1.10-20", 4, "192.168.1.10", "192.168.1.20"),  # last-octet shorthand
    ],
)
def test_parse_range_accepts_all_numeric_syntaxes(value, version, start, end):
    import ipaddress

    rng = parse_range(value)
    assert rng is not None
    assert rng.version == version
    assert rng.start == int(ipaddress.ip_address(start))
    assert rng.end == int(ipaddress.ip_address(end))


@pytest.mark.parametrize("value", ["example.com", "not-an-ip", "10.0.0.5-1", "10.0.0.0-oops"])
def test_parse_range_rejects_non_ranges(value):
    # Hostnames and malformed / reversed ranges fall back to None (hostname path).
    assert parse_range(value) is None


def test_full_range_exclude_blocks_targets_inside_it():
    checker = ScopeChecker(
        _rules(
            ("10.0.0.0/8", ScopeKind.INCLUDE),
            ("10.0.5.17-10.3.200.4", ScopeKind.EXCLUDE),  # spans multiple subnets
        )
    )
    # An address squarely inside the excluded range is out of scope …
    blocked = checker.classify("10.1.2.3")
    assert blocked.status is ScopeStatus.OUT_OF_SCOPE
    assert "10.0.5.17-10.3.200.4" in blocked.reason
    # … while one just outside it stays in scope.
    assert checker.classify("10.0.5.16").status is ScopeStatus.IN_SCOPE
    assert checker.classify("10.3.200.5").status is ScopeStatus.IN_SCOPE


def test_shorthand_range_used_as_include():
    checker = ScopeChecker(_rules(("192.168.1.10-20", ScopeKind.INCLUDE)))
    assert checker.classify("192.168.1.15").status is ScopeStatus.IN_SCOPE
    assert checker.classify("192.168.1.21").status is ScopeStatus.OUT_OF_SCOPE
    assert checker.classify("192.168.1.9").status is ScopeStatus.OUT_OF_SCOPE


def test_write_exclude_file_renders_range_as_cidrs(tmp_path):
    # An arbitrary multi-subnet range must land in the file as CIDR blocks — the
    # one syntax both nmap and masscan accept — not verbatim range text.
    rules = _rules(
        ("10.0.0.0/8", ScopeKind.INCLUDE),
        ("10.0.5.17-10.3.200.4", ScopeKind.EXCLUDE),
        ("192.168.1.5", ScopeKind.EXCLUDE),  # single IP stays bare
    )
    path = tmp_path / "excludes.txt"
    assert write_exclude_file(rules, path) == path
    lines = path.read_text().split()
    # The single IP is emitted bare; the range expands to only CIDR blocks.
    assert "192.168.1.5" in lines
    cidr_lines = [ln for ln in lines if ln != "192.168.1.5"]
    assert cidr_lines and all("/" in ln for ln in cidr_lines)
    # And the CIDRs exactly recover the original range — no more, no less.
    import ipaddress

    covered = [ip for ln in cidr_lines for ip in ipaddress.ip_network(ln)]
    assert covered[0] == ipaddress.ip_address("10.0.5.17")
    assert covered[-1] == ipaddress.ip_address("10.3.200.4")
    assert (
        len(covered)
        == int(ipaddress.ip_address("10.3.200.4")) - int(ipaddress.ip_address("10.0.5.17")) + 1
    )


def test_write_exclude_file_passes_through_hostnames(tmp_path):
    rules = _rules(("secret.example.com", ScopeKind.EXCLUDE))
    path = tmp_path / "excludes.txt"
    assert write_exclude_file(rules, path) == path
    assert path.read_text().split() == ["secret.example.com"]
