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


async def test_settings_panel_sets_nessus_keys(tmp_path, monkeypatch):
    # Clear env overrides so the screen reflects stored (not env) values.
    for var in ("NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="acme", open_scan=False)
        await pilot.press("s")  # dashboard -> settings
        await pilot.pause()

        app.screen.query_one("#nessus_url", Input).value = "https://nessus.local:8834"
        app.screen.query_one("#nessus_access_key", Input).value = "AAA"
        app.screen.query_one("#nessus_secret_key", Input).value = "BBB"
        await pilot.pause()
        await pilot.click("#save")
        await pilot.pause()

    saved = config.nessus_settings()
    assert saved.url == "https://nessus.local:8834"
    assert saved.access_key == "AAA"
    assert saved.secret_key == "BBB"
    assert saved.configured


async def test_settings_blank_key_keeps_stored(tmp_path, monkeypatch):
    for var in ("NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    config = _config(tmp_path)
    config.set_nessus_settings(access_key="KEEP-ACCESS", secret_key="KEEP-SECRET")
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="acme", open_scan=False)
        await pilot.press("s")
        await pilot.pause()

        # Key fields are masked + blank; changing only the URL must not wipe keys.
        assert app.screen.query_one("#nessus_access_key", Input).value == ""
        app.screen.query_one("#nessus_url", Input).value = "https://changed:8834"
        await pilot.pause()
        await pilot.click("#save")
        await pilot.pause()

    saved = config.nessus_settings()
    assert saved.url == "https://changed:8834"
    assert saved.access_key == "KEEP-ACCESS"
    assert saved.secret_key == "KEEP-SECRET"
