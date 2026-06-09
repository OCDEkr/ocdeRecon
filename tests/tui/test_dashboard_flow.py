"""Regression tests: q quits, and the dashboard reflects scans after returning."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import DataTable, Input, Static

from pentui.app import PentuiApp
from pentui.config import AppConfig

from ._helpers import start_engagement

FAKE_NMAP = """#!/usr/bin/env python3
import sys
out = None
for i, a in enumerate(sys.argv):
    if a == "-oX":
        out = sys.argv[i + 1]
if out:
    open(out, "w").write(
        \'<?xml version="1.0"?><nmaprun><host>\'
        \'<status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>\'
        \'<ports><port protocol="tcp" portid="80">\'
        \'<state state="open" reason="syn-ack"/><service name="http"/>\'
        \'</port></ports></host></nmaprun>\'
    )
print("done")
"""


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    script = tmp_path / "fakenmap"
    script.write_text(FAKE_NMAP)
    script.chmod(0o755)
    (config.user_tools_dir / "fakenmap.yaml").write_text(
        f"name: fakenmap\nbinary: {script}\ntarget: {{mode: append}}\n"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
    )
    return config


async def test_q_quits_from_dashboard(tmp_path):
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="q1", includes="10.0.0.0/24", open_scan=False)
        app.set_focus(None)
        await pilot.press("q")
        await pilot.pause()
        assert app._exit is True


async def test_dashboard_reflects_scan_after_return(tmp_path):
    app = PentuiApp(config=_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="dash", includes="10.0.0.0/24", targets="10.0.0.1")
        # On the tool-config screen with fakenmap as the default tool.
        app.screen.query_one("#targets", Input).value = "10.0.0.1"
        await pilot.pause()
        await pilot.click("#run")
        await app.workers.wait_for_complete()
        await pilot.pause()
        # Monitor -> tool config -> dashboard.
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()

        summary = str(app.screen.query_one("#summary", Static).render())
        assert "1 hosts" in summary
        table = app.screen.query_one("#scans", DataTable)
        tools = [table.get_row_at(r)[1] for r in range(table.row_count)]
        assert "fakenmap" in tools
