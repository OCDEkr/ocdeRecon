"""Engagement session — an open engagement DB plus its active project.

Opens (or creates) an engagement database and ensures its single ``project`` row
exists (one engagement file = one project). The selection screen drives which
engagement is opened; scope rules and targets live on that project.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from pentui.config import AppConfig
from pentui.core.models import Project
from pentui.persistence.db import init_db
from pentui.persistence.repositories import ProjectRepository

DEFAULT_ENGAGEMENT = "adhoc"


@dataclass(slots=True)
class Engagement:
    name: str
    conn: sqlite3.Connection
    project_id: int
    #: Per-engagement scan-output root (None = use the global/XDG default).
    output_dir: str | None = None

    @property
    def output_root_override(self) -> Path | None:
        """Expanded per-engagement output root, or None to fall back to config."""
        return Path(self.output_dir).expanduser() if self.output_dir else None


def open_engagement(config: AppConfig, name: str = DEFAULT_ENGAGEMENT) -> Engagement:
    conn = init_db(config.engagement_db_path(name))
    repo = ProjectRepository(conn)
    existing = repo.list()
    project = existing[0] if existing else repo.create(Project(name=name))
    assert project.id is not None
    return Engagement(name=name, conn=conn, project_id=project.id, output_dir=project.output_dir)
