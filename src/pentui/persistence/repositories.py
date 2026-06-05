"""CRUD repositories mapping domain models <-> SQLite rows (PROJECT.md §8).

Phase 0 provides ProjectRepository as the worked example proving the
model<->row round-trip; the remaining repositories follow the same pattern in
later phases (hosts deduped by (project_id, ip), ports by (host_id, number,
protocol), etc.).
"""

from __future__ import annotations

import sqlite3

from pentui.core.models import Project


class ProjectRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create(self, project: Project) -> Project:
        cur = self.conn.execute(
            "INSERT INTO project (name, client, notes) VALUES (?, ?, ?);",
            (project.name, project.client, project.notes),
        )
        self.conn.commit()
        assert cur.lastrowid is not None
        created = self.get(cur.lastrowid)
        assert created is not None
        return created

    def get(self, project_id: int) -> Project | None:
        row = self.conn.execute(
            "SELECT * FROM project WHERE id = ?;", (project_id,)
        ).fetchone()
        return self._from_row(row) if row else None

    def list(self) -> list[Project]:
        rows = self.conn.execute("SELECT * FROM project ORDER BY id;").fetchall()
        return [self._from_row(row) for row in rows]

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Project:
        return Project(
            id=row["id"],
            name=row["name"],
            client=row["client"],
            notes=row["notes"],
            created_at=row["created_at"],
        )
