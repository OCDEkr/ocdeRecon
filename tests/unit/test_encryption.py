"""SQLCipher encrypted-engagement tests (db layer + engagement open path)."""

from __future__ import annotations

import sqlite3

import pytest

from pentui.config import AppConfig
from pentui.core.models import Project
from pentui.persistence import db
from pentui.persistence.engagement import (
    ENCRYPTED_MARKER,
    is_encrypted,
    open_engagement,
)
from pentui.persistence.repositories import ProjectRepository


def test_encrypted_db_round_trips(tmp_path):
    path = tmp_path / "enc.db"
    conn = db.init_db(path, passphrase="s3cret")
    ProjectRepository(conn).create(Project(name="acme"))
    conn.close()

    # Reopen with the right passphrase: data is there.
    conn2 = db.init_db(path, passphrase="s3cret")
    assert [p.name for p in ProjectRepository(conn2).list()] == ["acme"]
    conn2.close()


def test_encrypted_file_is_not_plaintext_sqlite(tmp_path):
    path = tmp_path / "enc.db"
    db.init_db(path, passphrase="s3cret").close()
    # The header is encrypted, so the stdlib driver can't read it as a database.
    plain = sqlite3.connect(path)
    with pytest.raises(sqlite3.DatabaseError):
        plain.execute("SELECT count(*) FROM sqlite_master;")
    plain.close()


def test_wrong_passphrase_raises(tmp_path):
    path = tmp_path / "enc.db"
    db.init_db(path, passphrase="right").close()
    with pytest.raises(db.EncryptionError):
        db.init_db(path, passphrase="wrong")


def _config(tmp_path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


def test_open_engagement_encrypt_marks_and_reopens(tmp_path):
    config = _config(tmp_path)
    eng = open_engagement(config, "acme", passphrase="pw", encrypt=True)
    eng.conn.close()

    assert is_encrypted(config, "acme")
    assert (config.engagement_dir("acme") / ENCRYPTED_MARKER).exists()

    # Reopening (marker present) requires the passphrase and works with it.
    eng2 = open_engagement(config, "acme", passphrase="pw")
    assert eng2.project_id is not None
    eng2.conn.close()


def test_open_encrypted_engagement_without_passphrase_raises(tmp_path):
    config = _config(tmp_path)
    open_engagement(config, "acme", passphrase="pw", encrypt=True).conn.close()
    with pytest.raises(db.EncryptionError):
        open_engagement(config, "acme")


def test_plaintext_engagement_unaffected(tmp_path):
    config = _config(tmp_path)
    eng = open_engagement(config, "plain")
    eng.conn.close()
    assert not is_encrypted(config, "plain")
