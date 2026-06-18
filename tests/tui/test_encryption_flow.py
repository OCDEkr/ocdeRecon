"""TUI flow for SQLCipher-encrypted engagements: create, then unlock on open."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from textual.widgets import Input, ListView

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.persistence.engagement import is_encrypted, open_engagement

from ._helpers import start_engagement


def _make_config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


async def test_create_encrypted_engagement_from_form(tmp_path):
    config = _make_config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="secret", passphrase="hunter2", open_scan=False)

    assert is_encrypted(config, "secret")
    # The DB really is encrypted — the stdlib driver can't read its header.
    plain = sqlite3.connect(config.engagement_db_path("secret"))
    with pytest.raises(sqlite3.DatabaseError):
        plain.execute("SELECT count(*) FROM sqlite_master;")
    plain.close()


async def test_open_encrypted_engagement_prompts_for_passphrase(tmp_path):
    config = _make_config(tmp_path)
    # Pre-create an encrypted engagement on disk, then relaunch the app.
    open_engagement(config, "secret", passphrase="hunter2", encrypt=True).conn.close()

    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        view = app.screen.query_one("#existing", ListView)
        view.index = 0  # highlight the only engagement
        await pilot.pause()
        await pilot.press("enter")  # opening an encrypted engagement → passphrase modal
        await pilot.pause()

        # A wrong passphrase keeps us out (no engagement opened).
        app.screen.query_one("#value", Input).value = "wrong"
        await pilot.press("enter")
        await pilot.pause()
        assert app.engagement is None

        # Re-open and supply the right passphrase.
        view = app.screen.query_one("#existing", ListView)
        view.index = 0
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        app.screen.query_one("#value", Input).value = "hunter2"
        await pilot.press("enter")
        await pilot.pause()

        assert app.engagement is not None
        assert app.engagement.name == "secret"
