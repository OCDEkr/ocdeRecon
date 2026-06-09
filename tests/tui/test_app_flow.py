"""End-to-end TUI flow test driven by Textual's Pilot.

Uses a throwaway ``echo`` manifest so a real (harmless) command runs through the
config screen and scan monitor without needing nmap installed.
"""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Input, Static

from pentui.app import PentuiApp
from pentui.config import AppConfig

from ._helpers import start_engagement


def _make_config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    (config.user_tools_dir / "echo.yaml").write_text(
        "name: echo\n"
        "binary: echo\n"
        "target: {mode: append}\n"
        "options:\n"
        "  - {flag: '-n', label: 'No trailing newline', type: bool}\n"
    )
    return config


async def test_preview_updates_with_targets(tmp_path):
    app = PentuiApp(config=_make_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="prev")
        app.screen.query_one("#targets", Input).value = "alpha bravo"
        await pilot.pause()
        cmd = str(app.screen.query_one("#cmd", Static).render())
        assert cmd == "echo alpha bravo"


async def test_run_streams_to_completion(tmp_path):
    config = _make_config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="streamy")
        app.screen.query_one("#targets", Input).value = "hello world"
        await pilot.pause()
        await pilot.click("#run")
        await app.workers.wait_for_complete()
        await pilot.pause()

        status = str(app.screen.query_one("#status", Static).render())
        assert "Done" in status

    logs = list((config.engagement_dir("streamy") / "scans").glob("**/stdout.log"))
    assert len(logs) == 1
    assert logs[0].read_text() == "hello world\n"
