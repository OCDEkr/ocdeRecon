"""Schema/migration tests for the engagement database."""

from __future__ import annotations

import sqlite3

import pytest

from pentui.persistence import db


def test_init_db_creates_schema(tmp_path):
    conn = db.init_db(tmp_path / "engagement.db")

    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    }
    expected = {
        "project",
        "scope_rule",
        "target",
        "scan",
        "host",
        "port",
        "service",
        "finding",
        "workflow_run",
        "step_run",
        "audit_log",
        "schema_version",
    }
    assert expected <= tables


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "engagement.db"
    db.init_db(path).close()

    conn = db.init_db(path)  # second open should not re-apply migrations
    version = conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()["v"]
    assert version == db.SCHEMA_VERSION


def test_v1_database_upgrades_to_smb_signing_column(tmp_path):
    """An engagement DB created at v1 gains host.smb_signing on the next open."""
    path = tmp_path / "engagement.db"
    conn = db.connect(path)
    # Apply only the first migration to simulate a pre-existing v1 database.
    conn.executescript(db.MIGRATIONS[0])
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")
    conn.execute("INSERT INTO schema_version (version) VALUES (1);")
    conn.commit()
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(host);").fetchall()}
    assert "smb_signing" not in cols
    conn.close()

    conn = db.init_db(path)  # reopening applies pending migrations
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(host);").fetchall()}
    assert "smb_signing" in cols
    version = conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()["v"]
    assert version == db.SCHEMA_VERSION


def test_v1_database_upgrades_to_project_output_dir_column(tmp_path):
    """An engagement DB created at v1 gains project.output_dir on the next open."""
    path = tmp_path / "engagement.db"
    conn = db.connect(path)
    conn.executescript(db.MIGRATIONS[0])  # v1 only
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")
    conn.execute("INSERT INTO schema_version (version) VALUES (1);")
    conn.commit()
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(project);").fetchall()}
    assert "output_dir" not in cols
    conn.close()

    conn = db.init_db(path)  # reopening applies pending migrations
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(project);").fetchall()}
    assert "output_dir" in cols
    version = conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()["v"]
    assert version == db.SCHEMA_VERSION


def test_project_output_dir_round_trips_through_repository(tmp_path):
    from pentui.core.models import Project
    from pentui.persistence.repositories import ProjectRepository

    conn = db.init_db(tmp_path / "engagement.db")
    repo = ProjectRepository(conn)
    created = repo.create(Project(name="acme"))
    assert created.output_dir is None  # defaults NULL
    conn.execute("UPDATE project SET output_dir = ? WHERE id = ?;", ("~/pentests/acme", created.id))
    conn.commit()
    assert repo.get(created.id).output_dir == "~/pentests/acme"


def test_foreign_keys_enforced(tmp_path):
    conn = db.init_db(tmp_path / "engagement.db")
    # Inserting a scope_rule for a non-existent project must fail.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO scope_rule (project_id, value, kind) "
            "VALUES (999, '10.0.0.0/24', 'include');"
        )
        conn.commit()
