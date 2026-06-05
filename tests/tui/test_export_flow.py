"""TUI test: export reports from the dashboard."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Checkbox

from pentui.app import PentuiApp
from pentui.config import AppConfig

from ._helpers import start_engagement


def _make_config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


async def test_export_writes_selected_formats(tmp_path):
    config = _make_config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="rep", includes="10.0.0.0/24", open_scan=False)
        await pilot.press("e")
        await pilot.pause()

        # Defaults: Markdown + HTML on; also enable JSON.
        app.screen.query_one("#fmt-json", Checkbox).value = True
        await pilot.pause()
        await pilot.click("#export")
        await pilot.pause()

    reports = sorted(p.suffix for p in (config.reports_dir("rep")).glob("*"))
    assert reports == [".html", ".json", ".md"]
