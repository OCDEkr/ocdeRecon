"""TUI test: create a tool profile from the scan-config screen."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Button, Input, Select, Static

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.core.manifest import load_manifest

from ._helpers import start_engagement


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


async def test_value_option_default_is_prefilled(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(120, 50)) as pilot:
        await start_engagement(pilot, name="dflt", includes="10.0.0.0/24")
        screen = app.screen
        screen.query_one("#tool", Select).value = "gowitness"
        await pilot.pause()
        # gowitness --threads/--timeout defaults pre-fill, so they're in the command.
        opts = screen._current_options()
        assert opts.get("--threads") == "16"
        assert opts.get("--timeout") == "15"
        assert "--threads 16" in str(screen.query_one("#cmd", Static).render())


async def test_save_as_profile_writes_user_manifest(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(120, 50)) as pilot:
        await start_engagement(pilot, name="prof", includes="10.0.0.0/24")
        screen = app.screen
        screen.query_one("#tool", Select).value = "nmap"
        await pilot.pause()
        screen.query_one("#profile", Select).value = "Service scan"
        screen.query_one("#extra-args", Input).value = "--top-ports 50"
        await pilot.pause()

        # Open the name prompt and confirm.
        screen.query_one("#save-profile", Button).press()
        await pilot.pause()
        app.screen.query_one("#value", Input).value = "web-deep"
        app.screen.query_one("#ok", Button).press()
        await pilot.pause()

        # Written as a user manifest override that merges the new profile in.
        path = config.user_tools_dir / "nmap.yaml"
        assert path.exists()
        manifest = load_manifest(path)
        names = {p.name for p in manifest.profiles}
        assert {"Quick", "Service scan", "web-deep"} <= names  # merged, not replaced
        args = manifest.profile("web-deep").args
        assert "-sV" in args and "--top-ports" in args and "50" in args

        # Immediately available in the (reloaded) profile dropdown.
        assert app.screen.manifest.profile("web-deep") is not None
