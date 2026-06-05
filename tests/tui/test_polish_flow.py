"""TUI tests for Phase 6 polish: theme toggle persistence and audit-log viewer."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import DataTable

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.tui.themes import COLORBLIND_THEME, DEFAULT_THEME

from ._helpers import start_engagement


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    (config.user_tools_dir / "echo.yaml").write_text(
        "name: echo\nbinary: echo\ntarget: {mode: append}\n"
    )
    return config


async def test_theme_toggle_persists(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        assert app.theme == DEFAULT_THEME
        await pilot.press("f2")
        await pilot.pause()
        assert app.theme == COLORBLIND_THEME

    # Persisted, so a fresh app starts in the chosen theme.
    assert config.load_settings()["theme"] == COLORBLIND_THEME
    app2 = PentuiApp(config=config)
    async with app2.run_test(size=(100, 50)):
        assert app2.theme == COLORBLIND_THEME


async def test_audit_log_screen_shows_override(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        # Define scope, then run an out-of-scope target and override it.
        await start_engagement(pilot, name="aud", includes="10.0.0.0/24")
        from textual.widgets import Input

        app.screen.query_one("#targets", Input).value = "8.8.8.8"
        await pilot.pause()
        await pilot.click("#run")
        await pilot.pause()
        await pilot.click("#override")
        await app.workers.wait_for_complete()
        await pilot.pause()

        # Monitor -> tool config -> dashboard, then open the audit log.
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()

        table = app.screen.query_one("#audit", DataTable)
        actions = [table.get_row_at(r)[1] for r in range(table.row_count)]
        assert "scope_override" in actions
