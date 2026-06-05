"""Regression tests for the engagement-selection screen."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Input, ListView

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.tui.screens.modals import ConfirmModal
from pentui.tui.screens.project_select import ProjectSelectScreen

from ._helpers import start_engagement


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


async def test_created_engagement_appears_on_return(tmp_path):
    """Creating an engagement then returning shows it in the list (and clears the form)."""
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="alpha", includes="10.0.0.0/24", open_scan=False)
        # On the dashboard; go back to the engagement list.
        await pilot.press("escape")
        await pilot.pause()

        assert isinstance(app.screen, ProjectSelectScreen)
        view = app.screen.query_one("#existing", ListView)
        names = [item.name for item in view.children]
        assert names == ["alpha"]
        # Form was reset so the previous name doesn't linger.
        assert app.screen.query_one("#name", Input).value == ""


async def test_can_open_existing_engagement_from_list(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="beta", open_scan=False)
        await pilot.press("escape")
        await pilot.pause()

        # Select the existing engagement from the list -> reopens its dashboard.
        view = app.screen.query_one("#existing", ListView)
        view.index = 0
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        assert app.engagement is not None
        assert app.engagement.name == "beta"


async def test_engagement_list_is_visible(tmp_path):
    """Regression: the list must get real height (the create form once starved it to 0)."""
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="visible", open_scan=False)
        await pilot.press("escape")
        await pilot.pause()
        view = app.screen.query_one("#existing", ListView)
        # The list once collapsed to height 0; it must now have drawable rows.
        assert view.size.height >= 1
        assert len(view.children) == 1


async def test_delete_engagement_with_confirm(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="trash", open_scan=False)
        await pilot.press("escape")
        await pilot.pause()

        view = app.screen.query_one("#existing", ListView)
        view.index = 0
        await pilot.pause()
        await pilot.press("d")
        await pilot.pause()

        assert isinstance(app.screen, ConfirmModal)
        await pilot.click("#confirm")
        await pilot.pause()

        assert not config.engagement_dir("trash").exists()
        assert list(app.screen.query_one("#existing", ListView).children) == []


async def test_delete_cancel_keeps_engagement(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="keep", open_scan=False)
        await pilot.press("escape")
        await pilot.pause()

        app.screen.query_one("#existing", ListView).index = 0
        await pilot.pause()
        await pilot.press("d")
        await pilot.pause()
        await pilot.click("#cancel")
        await pilot.pause()

        assert config.engagement_dir("keep").exists()
        names = [i.name for i in app.screen.query_one("#existing", ListView).children]
        assert names == ["keep"]
