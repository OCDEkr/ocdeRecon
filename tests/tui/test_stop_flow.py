"""TUI test: the Stop control terminates a running scan."""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Input, Select, Static

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.core.models import ScanStatus
from pentui.persistence.repositories import ScanRepository

from ._helpers import start_engagement

SLEEPER = "#!/usr/bin/env python3\nimport time\nprint('starting', flush=True)\ntime.sleep(30)\n"


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    script = tmp_path / "sleeper"
    script.write_text(SLEEPER)
    script.chmod(0o755)
    (config.user_tools_dir / "sleeper.yaml").write_text(
        f"name: sleeper\nbinary: {script}\ntarget: {{mode: append}}\n"
    )
    return config


async def test_stop_terminates_running_scan(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="stoppy", targets="127.0.0.1")
        # Select the sleeper tool (gowitness sorts first and would be the default).
        app.screen.query_one("#tool", Select).value = "sleeper"
        await pilot.pause()
        app.screen.query_one("#targets", Input).value = "127.0.0.1"
        await pilot.pause()
        await pilot.click("#run")
        await pilot.pause()

        monitor = app.screen
        # Wait until the subprocess has actually started.
        for _ in range(100):
            if monitor._proc is not None:
                break
            await asyncio.sleep(0.02)
        assert monitor._proc is not None

        await pilot.press("s")
        await app.workers.wait_for_complete()
        await pilot.pause()

        assert "Stopped" in str(monitor.query_one("#status", Static).render())
        eng = app.engagement
        scan = ScanRepository(eng.conn).list_recent(eng.project_id)[0]
        assert scan.status is ScanStatus.CANCELLED
