"""Engagement session — an open engagement DB plus its active project.

Phase 2 bridge: opens (or creates) an engagement database and ensures a single
default project so scans have somewhere to persist. Phase 3 replaces the default
project with real project/target management and selection.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

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


def open_engagement(config: AppConfig, name: str = DEFAULT_ENGAGEMENT) -> Engagement:
    conn = init_db(config.engagement_db_path(name))
    repo = ProjectRepository(conn)
    existing = repo.list()
    project = existing[0] if existing else repo.create(Project(name=name))
    assert project.id is not None
    return Engagement(name=name, conn=conn, project_id=project.id)
