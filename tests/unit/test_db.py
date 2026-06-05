"""Schema/migration tests for the engagement database."""

from __future__ import annotations

import sqlite3

import pytest

from pentui.persistence import db


def test_init_db_creates_schema(tmp_path):
    conn = db.init_db(tmp_path / "engagement.db")

    tables = {
        row["name"]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table';"
        ).fetchall()
    }
    expected = {
        "project", "scope_rule", "target", "scan", "host", "port", "service",
        "finding", "workflow_run", "step_run", "audit_log", "schema_version",
    }
    assert expected <= tables


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "engagement.db"
    db.init_db(path).close()

    conn = db.init_db(path)  # second open should not re-apply migrations
    version = conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()["v"]
    assert version == db.SCHEMA_VERSION


def test_foreign_keys_enforced(tmp_path):
    conn = db.init_db(tmp_path / "engagement.db")
    # Inserting a scope_rule for a non-existent project must fail.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO scope_rule (project_id, value, kind) "
            "VALUES (999, '10.0.0.0/24', 'include');"
        )
        conn.commit()
