"""TUI test: the settings panel sets a per-tool output directory override."""

from __future__ import annotations

from pathlib import Path

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


async def test_settings_panel_sets_tool_output_dir(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="acme", open_scan=False)
        await pilot.press("s")  # dashboard -> settings
        await pilot.pause()

        app.screen._inputs["echo"].value = "/mnt/evidence/echo"
        await pilot.pause()
        await pilot.click("#save")
        await pilot.pause()

    # Persisted, and the override now drives the per-engagement scan path.
    assert config.tool_output_dirs()["echo"] == "/mnt/evidence/echo"
    assert config.scan_dir("acme", 3, tool="echo") == Path("/mnt/evidence/echo/acme/3")
