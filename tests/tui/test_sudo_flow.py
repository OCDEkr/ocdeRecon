"""Sudo password handling: cache path + prompt-on-root wiring.

Real `sudo` is never invoked here — the prompt test cancels before validation.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from textual.widgets import Button, Input, Select

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.persistence.repositories import ScanRepository
from pentui.tui.screens.modals import TextPromptModal

from ._helpers import start_engagement


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    (config.user_tools_dir / "rootcat.yaml").write_text(
        "name: rootcat\nbinary: echo\nrequires_root: true\ntarget: {mode: append}\n"
    )
    return config


async def test_cached_sudo_password_returns_without_prompt(tmp_path):
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 40)):
        app.sudo_password = "preset"
        # Already cached -> returns immediately (no modal, no real `sudo` call).
        assert await app.request_sudo_password() == "preset"


async def test_root_tool_prompts_for_password(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root; no sudo prompt expected")
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="rooty")
        app.screen.query_one("#tool", Select).value = "rootcat"
        await pilot.pause()
        app.screen.query_one("#targets", Input).value = "10.0.0.1"
        await pilot.pause()
        await pilot.click("#run")
        await pilot.pause()

        # A root tool asks for the sudo password before running.
        assert isinstance(app.screen, TextPromptModal)
        app.screen.query_one("#cancel", Button).press()
        await pilot.pause()

        # Cancelled -> no scan was created (and no real sudo call happened).
        eng = app.engagement
        assert ScanRepository(eng.conn).list_recent(eng.project_id) == []
