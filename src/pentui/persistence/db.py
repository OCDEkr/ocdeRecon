"""SQLite connection + schema migrations (PROJECT.md §8).

One database file per engagement. The schema is applied through an ordered list
of migrations tracked in a ``schema_version`` table, so future phases can evolve
the schema additively.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

#: Ordered migrations. Each entry is the full SQL applied when upgrading TO that
#: version from the previous one. Append new migrations; never edit shipped ones.
MIGRATIONS: list[str] = [
    # ---- v1: initial schema -------------------------------------------------
    """
    CREATE TABLE project (
        id          INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        client      TEXT,
        notes       TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE scope_rule (
        id          INTEGER PRIMARY KEY,
        project_id  INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
        value       TEXT NOT NULL,
        kind        TEXT NOT NULL CHECK (kind IN ('include', 'exclude'))
    );

    CREATE TABLE target (
        id          INTEGER PRIMARY KEY,
        project_id  INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
        value       TEXT NOT NULL,
        source      TEXT NOT NULL DEFAULT 'manual',
        added_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE workflow_run (
        id              INTEGER PRIMARY KEY,
        project_id      INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
        workflow_name   TEXT NOT NULL,
        definition_json TEXT,
        status          TEXT NOT NULL DEFAULT 'queued',
        unattended      INTEGER NOT NULL DEFAULT 0,
        started_at      TEXT,
        finished_at     TEXT
    );

    CREATE TABLE step_run (
        id               INTEGER PRIMARY KEY,
        workflow_run_id  INTEGER NOT NULL REFERENCES workflow_run(id) ON DELETE CASCADE,
        step_id          TEXT NOT NULL,
        tool             TEXT NOT NULL,
        scan_id          INTEGER,
        status           TEXT NOT NULL DEFAULT 'queued',
        gate_state       TEXT NOT NULL DEFAULT 'auto',
        started_at       TEXT,
        finished_at      TEXT
    );

    CREATE TABLE scan (
        id               INTEGER PRIMARY KEY,
        project_id       INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
        tool             TEXT NOT NULL,
        profile          TEXT,
        command_str      TEXT,
        args_json        TEXT,
        status           TEXT NOT NULL DEFAULT 'queued',
        exit_code        INTEGER,
        ran_as_root      INTEGER NOT NULL DEFAULT 0,
        started_at       TEXT,
        finished_at      TEXT,
        raw_output_path  TEXT,
        artifact_path    TEXT,
        step_run_id      INTEGER REFERENCES step_run(id) ON DELETE SET NULL
    );

    CREATE TABLE host (
        id          INTEGER PRIMARY KEY,
        project_id  INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
        ip          TEXT NOT NULL,
        hostname    TEXT,
        state       TEXT NOT NULL DEFAULT 'up',
        first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
        last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE (project_id, ip)
    );

    CREATE TABLE port (
        id                     INTEGER PRIMARY KEY,
        host_id                INTEGER NOT NULL REFERENCES host(id) ON DELETE CASCADE,
        discovered_by_scan_id  INTEGER REFERENCES scan(id) ON DELETE SET NULL,
        number                 INTEGER NOT NULL,
        protocol               TEXT NOT NULL DEFAULT 'tcp',
        state                  TEXT NOT NULL DEFAULT 'open',
        reason                 TEXT,
        UNIQUE (host_id, number, protocol)
    );

    CREATE TABLE service (
        id          INTEGER PRIMARY KEY,
        port_id     INTEGER NOT NULL REFERENCES port(id) ON DELETE CASCADE,
        name        TEXT,
        product     TEXT,
        version     TEXT,
        extrainfo   TEXT,
        cpe         TEXT
    );

    CREATE TABLE finding (
        id          INTEGER PRIMARY KEY,
        project_id  INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
        host_id     INTEGER REFERENCES host(id) ON DELETE CASCADE,
        scan_id     INTEGER REFERENCES scan(id) ON DELETE SET NULL,
        source_tool TEXT NOT NULL,
        severity    TEXT NOT NULL DEFAULT 'unknown',
        title       TEXT NOT NULL,
        detail      TEXT,
        created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE audit_log (
        id          INTEGER PRIMARY KEY,
        project_id  INTEGER REFERENCES project(id) ON DELETE CASCADE,
        ts          TEXT NOT NULL DEFAULT (datetime('now')),
        action      TEXT NOT NULL,
        detail      TEXT
    );

    CREATE INDEX idx_host_project ON host(project_id);
    CREATE INDEX idx_port_host ON port(host_id);
    CREATE INDEX idx_service_port ON service(port_id);
    CREATE INDEX idx_finding_project ON finding(project_id);
    CREATE INDEX idx_scan_project ON scan(project_id);
    CREATE INDEX idx_steprun_run ON step_run(workflow_run_id);
    """,
    # ---- v2: SMB signing state per host (runfinger -> relay targeting) -------
    # NULL = unknown/not fingerprinted. 'required' = signing enforced.
    # 'disabled' = signing not required -> an NTLM-relay target.
    """
    ALTER TABLE host ADD COLUMN smb_signing TEXT;
    """,
    # ---- v3: domain-controller flag per host (DC discovery) -----------------
    # NULL = unknown/not checked. 1 = identified domain controller (answers LDAP).
    """
    ALTER TABLE host ADD COLUMN is_dc INTEGER;
    """,
    # ---- v4: per-engagement scan-output root --------------------------------
    # NULL = use the global output_root setting / XDG default. Set on the
    # create-engagement form so an unattended kickoff writes to the chosen folder.
    """
    ALTER TABLE project ADD COLUMN output_dir TEXT;
    """,
]

SCHEMA_VERSION = len(MIGRATIONS)


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with foreign keys enforced and row access by name."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _current_version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);")
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()
    return row["v"] or 0


def migrate(conn: sqlite3.Connection) -> int:
    """Apply any pending migrations. Returns the resulting schema version."""
    current = _current_version(conn)
    for version in range(current + 1, len(MIGRATIONS) + 1):
        conn.executescript(MIGRATIONS[version - 1])
        conn.execute("INSERT INTO schema_version (version) VALUES (?);", (version,))
        conn.commit()
    return _current_version(conn)


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Open ``db_path``, applying migrations so the schema is current."""
    conn = connect(db_path)
    migrate(conn)
    return conn
