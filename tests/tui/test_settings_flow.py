"""TUI test: the settings panel sets the scan-output root."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Input

from pentui.app import PentuiApp
from pentui.config import AppConfig

from ._helpers import start_engagement


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    (config.user_tools_dir / "echo.yaml").write_text(
        "name: echo\nbinary: echo\ntarget: {mode: append}\n"
    )
    return config


async def test_settings_panel_sets_output_root(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="acme", open_scan=False)
        await pilot.press("s")  # dashboard -> settings
        await pilot.pause()

        app.screen.query_one("#root", Input).value = "/home/op/pentests"
        await pilot.pause()
        await pilot.click("#save")
        await pilot.pause()

    # Persisted, and it now drives the per-engagement / per-tool scan path.
    assert config.output_root() == Path("/home/op/pentests")
    assert config.scan_dir("acme", 3, tool="echo") == Path("/home/op/pentests/acme/scans/echo/3")
