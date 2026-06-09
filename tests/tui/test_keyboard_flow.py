"""Phase A: keyboard-first navigation — action-button bindings, theme, jump-home.

Drives the same throwaway ``echo`` manifest as the other flow tests so a real
(harmless) command exercises the keyboard path end to end.
"""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Checkbox, Input, Static

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.tui.screens.dashboard import DashboardScreen
from pentui.tui.screens.project_select import ProjectSelectScreen
from pentui.tui.screens.settings import SettingsScreen

from ._helpers import start_engagement


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    (config.user_tools_dir / "echo.yaml").write_text(
        "name: echo\nbinary: echo\ntarget: {mode: append}\n"
    )
    return config


async def test_ctrl_n_creates_engagement(tmp_path):
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        assert isinstance(app.screen, ProjectSelectScreen)
        app.screen.query_one("#name", Input).value = "kbd"
        await pilot.pause()
        await pilot.press("ctrl+n")  # Create & open without touching the mouse
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)


async def test_ctrl_r_runs_scan(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="kbdrun")  # lands on ToolConfigScreen
        app.screen.query_one("#targets", Input).value = "hello world"
        await pilot.pause()
        await pilot.press("ctrl+r")  # Run scan via keyboard
        await app.workers.wait_for_complete()
        await pilot.pause()
        status = str(app.screen.query_one("#status", Static).render())
        assert "Done" in status

    logs = list((config.engagement_dir("kbdrun") / "scans").glob("**/stdout.log"))
    assert logs and logs[0].read_text() == "hello world\n"


async def test_ctrl_d_jumps_to_dashboard(tmp_path):
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="jump")  # ToolConfigScreen on top
        assert not isinstance(app.screen, DashboardScreen)
        await pilot.press("ctrl+d")  # jump home
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)


async def test_settings_cb_palette_toggles_theme_live(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="pal", open_scan=False)  # Dashboard
        await pilot.press("s")  # open Settings
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)
        assert app.theme == "pentui-dark"

        app.screen.query_one("#cb", Checkbox).value = True
        await pilot.pause()
        assert app.theme == "pentui-dark-cb"  # applied live

        await pilot.press("ctrl+s")  # Save via keyboard
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)

    assert config.palette() == "cb"  # persisted
