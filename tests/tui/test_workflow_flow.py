"""End-to-end workflow TUI: launch a chain and watch it run to completion."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Checkbox, DataTable, ListView

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.persistence.repositories import HostRepository

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
print("fake nmap done")
"""


def _make_config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    script = tmp_path / "fakenmap"
    script.write_text(FAKE_NMAP)
    script.chmod(0o755)
    (config.user_tools_dir / "fakenmap.yaml").write_text(
        f"name: fakenmap\nbinary: {script}\ntarget: {{mode: append}}\n"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
    )
    (config.user_tools_dir / "echo.yaml").write_text(
        "name: echo\nbinary: echo\ntarget: {mode: append}\n"
    )
    (config.user_workflows_dir / "chain.yaml").write_text(
        "name: chain\nsteps:\n"
        "  - {id: discover, tool: fakenmap, targets: {from: project}}\n"
        "  - id: shots\n"
        "    tool: echo\n"
        "    after: [discover]\n"
        "    input: {from: hosts, where: {port_open_in: [80]}, as: target_urls}\n"
    )
    return config


async def test_launch_workflow_runs_chain(tmp_path):
    config = _make_config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="auto", targets="10.0.0.1", open_scan=False)
        # Dashboard -> workflows
        await pilot.press("w")
        await pilot.pause()

        app.screen.query_one("#workflows", ListView).index = 0  # "chain" sorts first
        app.screen.query_one("#unattended", Checkbox).value = True
        await pilot.pause()
        await pilot.click("#launch")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()

        # The chain discovered + persisted a host, then fed it to the next tool.
        eng = app.engagement
        hosts = HostRepository(eng.conn).list_for_project(eng.project_id)
        assert [h.ip for h in hosts] == ["10.0.0.1"]

        table = app.screen.query_one("#steps", DataTable)
        assert table.get_cell("discover", "status") == "done"
        assert table.get_cell("shots", "status") == "done"
