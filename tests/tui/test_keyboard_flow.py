"""Phase A: keyboard-first navigation — action-button bindings, theme, jump-home.

Drives the same throwaway ``echo`` manifest as the other flow tests so a real
(harmless) command exercises the keyboard path end to end.
"""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Checkbox, DataTable, Input, ListView, Static

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.persistence.engagement import open_engagement
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
        await start_engagement(pilot, name="kbdrun", tool="echo")  # lands on ToolConfigScreen
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


async def test_arrow_keys_move_between_form_fields(tmp_path):
    """↓/↑ walk the new-engagement Inputs in both directions (no Tab needed)."""
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        assert isinstance(app.screen, ProjectSelectScreen)
        app.screen.query_one("#name", Input).focus()
        await pilot.pause()
        await pilot.press("down")
        assert app.focused is not None and app.focused.id == "client"
        await pilot.press("down")
        assert app.focused is not None and app.focused.id == "includes"
        await pilot.press("up")  # go back without Tab-cycling around
        assert app.focused is not None and app.focused.id == "client"


async def test_arrow_down_in_scroll_moves_focus_not_scroll(tmp_path):
    """Inside the Settings VerticalScroll, ↓ advances focus rather than scrolling
    the container (priority binding wins over the scroll binding)."""
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="scroll", open_scan=False)  # Dashboard
        await pilot.press("s")  # open Settings
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)
        app.screen.query_one("#root", Input).focus()
        await pilot.pause()
        await pilot.press("down")  # -> the colour-blind checkbox
        assert app.focused is not None and app.focused.id == "cb"
        await pilot.press("down")  # -> next Input in the scrolled body
        assert app.focused is not None and app.focused.id == "nessus_url"


async def test_arrow_navigates_list_then_escapes_into_form(tmp_path):
    """↓ walks the engagement list, then steps out into the form at the bottom
    edge (instead of wrapping back to the top and trapping focus)."""
    config = _config(tmp_path)
    open_engagement(config, "alpha").conn.close()  # two engagements -> a 2-item list
    open_engagement(config, "bravo").conn.close()
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        assert isinstance(app.screen, ProjectSelectScreen)
        existing = app.screen.query_one("#existing", ListView)
        existing.focus()
        await pilot.pause()
        assert app.focused is existing and existing.index is None
        await pilot.press("down")  # highlight the first item
        assert app.focused is existing and existing.index == 0
        await pilot.press("down")  # mid-list: stays in the list, moves highlight
        assert app.focused is existing and existing.index == 1
        await pilot.press("down")  # bottom edge: escape into the form
        assert app.focused is not None and app.focused.id == "name"


async def test_arrow_keeps_focus_in_datatable(tmp_path):
    """A non-list nav widget (the dashboard scans table) keeps the arrows even at
    its edge — only ListView/SelectionList opt into edge-escape."""
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="tbl", open_scan=False)  # Dashboard
        assert isinstance(app.screen, DashboardScreen)
        scans = app.screen.query_one("#scans", DataTable)
        scans.focus()
        await pilot.pause()
        await pilot.press("down")
        assert app.focused is scans  # focus did not jump out of the table


async def test_left_right_still_edit_text(tmp_path):
    """←/→ stay as cursor movement inside an Input (focus unchanged)."""
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        name = app.screen.query_one("#name", Input)
        name.value = "abc"
        name.focus()
        await pilot.pause()
        await pilot.press("left")
        assert app.focused is name  # cursor moved, focus did not
