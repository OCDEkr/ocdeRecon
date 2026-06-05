"""Tests for scope-rule, target, audit-log, and recent-scan repositories."""

from __future__ import annotations

from pentui.core.models import Scan, ScopeKind, TargetSource
from pentui.persistence import db
from pentui.persistence.repositories import (
    AuditLogRepository,
    ScanRepository,
    ScopeRuleRepository,
    TargetRepository,
)


def _conn(tmp_path):
    conn = db.init_db(tmp_path / "e.db")
    conn.execute("INSERT INTO project (id, name) VALUES (1, 'p');")
    conn.commit()
    return conn


def test_scope_rule_repository(tmp_path):
    conn = _conn(tmp_path)
    repo = ScopeRuleRepository(conn)
    repo.create(1, "10.0.0.0/24", ScopeKind.INCLUDE)
    repo.create(1, "10.0.0.13", ScopeKind.EXCLUDE)
    rules = repo.list_for_project(1)
    assert {(r.value, r.kind) for r in rules} == {
        ("10.0.0.0/24", ScopeKind.INCLUDE),
        ("10.0.0.13", ScopeKind.EXCLUDE),
    }


def test_target_repository(tmp_path):
    conn = _conn(tmp_path)
    repo = TargetRepository(conn)
    repo.create(1, "10.0.0.5")
    repo.create(1, "app.example", TargetSource.MANUAL)
    targets = repo.list_for_project(1)
    assert [t.value for t in targets] == ["10.0.0.5", "app.example"]


def test_audit_log_repository(tmp_path):
    conn = _conn(tmp_path)
    repo = AuditLogRepository(conn)
    repo.log(1, "scope_override", "scanned 8.8.8.8 out of scope")
    repo.log(1, "sudo_run", "nmap -sS")
    entries = repo.list_for_project(1)
    assert [a for _, a, _ in entries] == ["scope_override", "sudo_run"]


def test_scan_list_recent_orders_newest_first(tmp_path):
    conn = _conn(tmp_path)
    repo = ScanRepository(conn)
    first = repo.create(Scan(project_id=1, tool="nmap"))
    second = repo.create(Scan(project_id=1, tool="nmap"))
    recent = repo.list_recent(1)
    assert [s.id for s in recent] == [second.id, first.id]
