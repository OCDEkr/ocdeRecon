"""TUI test: build a workflow interactively, save it, and see it on the launch list."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Button, Checkbox, Input, ListView, Select

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.core.workflow import load_workflow

from ._helpers import start_engagement


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


async def test_build_save_and_list_workflow(tmp_path):
    config = _config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(120, 50)) as pilot:
        await start_engagement(pilot, name="bld", includes="10.0.0.0/24", open_scan=False)
        await pilot.press("w")      # dashboard -> workflow launch
        await pilot.pause()
        await pilot.press("b")      # launch -> builder
        await pilot.pause()

        screen = app.screen
        screen.query_one("#wf-name", Input).value = "mychain"

        # Step 1: nmap on the project targets.
        screen.query_one("#step-tool", Select).value = "nmap"
        screen.query_one("#step-feed", Select).value = "project"
        await pilot.pause()
        screen.query_one("#add-step", Button).press()
        await pilot.pause()

        # Step 2: gowitness fed by nmap's discovered web ports.
        screen.query_one("#step-tool", Select).value = "gowitness"
        await pilot.pause()
        screen.query_one("#step-after", Select).value = "nmap"
        screen.query_one("#step-feed", Select).value = "web"
        screen.query_one("#step-gate", Checkbox).value = True
        await pilot.pause()
        screen.query_one("#add-step", Button).press()
        await pilot.pause()

        screen.query_one("#save", Button).press()
        await pilot.pause()

        # Saved to disk as valid YAML.
        path = config.user_workflows_dir / "mychain.yaml"
        assert path.exists()
        wf = load_workflow(path)
        assert [s.id for s in wf.steps] == ["nmap", "gowitness"]
        assert wf.steps[1].after == ["nmap"]
        assert wf.steps[1].input.as_.value == "target_urls"
        assert wf.steps[1].gate is True

        # Back on the launch screen, the new workflow is listed.
        await pilot.press("escape")
        await pilot.pause()
        names = [i.name for i in app.screen.query_one("#workflows", ListView).children]
        assert "mychain" in names
