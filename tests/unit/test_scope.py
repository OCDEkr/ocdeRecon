"""Scope classification tests."""

from __future__ import annotations

import pytest

from pentui.core.models import ScopeKind, ScopeRule
from pentui.core.scope import ScopeChecker, ScopeStatus, classify_targets, write_exclude_file


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
