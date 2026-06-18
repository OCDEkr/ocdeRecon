"""Engagement session — an open engagement DB plus its active project.

Opens (or creates) an engagement database and ensures its single ``project`` row
exists (one engagement file = one project). The selection screen drives which
engagement is opened; scope rules and targets live on that project.

An engagement may be **encrypted** (SQLCipher). Whether it is can't live inside
the (encrypted) DB — you need it *before* opening — so it's recorded by a sidecar
``.encrypted`` marker file in the engagement directory. :func:`is_encrypted`
checks it so callers know to prompt for a passphrase first.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from pentui.config import AppConfig
from pentui.core.models import Project
from pentui.persistence.db import EncryptionError, init_db
from pentui.persistence.repositories import ProjectRepository

DEFAULT_ENGAGEMENT = "adhoc"
#: Sidecar file (in the engagement dir) marking the DB as SQLCipher-encrypted.
ENCRYPTED_MARKER = ".encrypted"


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


def is_encrypted(config: AppConfig, name: str) -> bool:
    """Whether engagement ``name`` is marked SQLCipher-encrypted."""
    return (config.engagement_dir(name) / ENCRYPTED_MARKER).exists()


def open_engagement(
    config: AppConfig,
    name: str = DEFAULT_ENGAGEMENT,
    *,
    passphrase: str | None = None,
    encrypt: bool = False,
) -> Engagement:
    """Open (or create) an engagement DB and ensure its project row.

    ``encrypt=True`` creates a new encrypted engagement (requires ``passphrase``).
    An already-encrypted engagement (``.encrypted`` marker present) also requires
    a ``passphrase``; a wrong one raises :class:`EncryptionError`.
    """
    marker = config.engagement_dir(name) / ENCRYPTED_MARKER
    encrypted = encrypt or marker.exists()
    if encrypted and not passphrase:
        raise EncryptionError(f"engagement {name!r} is encrypted; a passphrase is required")

    conn = init_db(config.engagement_db_path(name), passphrase=passphrase if encrypted else None)
    # Mark a freshly-created encrypted DB only after it opened/keyed successfully.
    if encrypt and not marker.exists():
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("sqlcipher\n")

    repo = ProjectRepository(conn)
    existing = repo.list()
    project = existing[0] if existing else repo.create(Project(name=name))
    assert project.id is not None
    return Engagement(name=name, conn=conn, project_id=project.id, output_dir=project.output_dir)
