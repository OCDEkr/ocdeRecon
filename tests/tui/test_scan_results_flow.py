"""End-to-end Phase 2 flow: run a tool, parse its XML, persist, and browse.

Uses a fake ``nmap`` (a tiny executable that writes XML to its ``-oX`` path) so
the nmap_xml parser + persistence + results browser are exercised without a real
nmap scan.
"""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Input, Static, Tree

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.persistence.repositories import HostRepository, PortRepository

from ._helpers import start_engagement

FAKE_NMAP = '''#!/usr/bin/env python3
import sys

out = None
argv = sys.argv
for i, a in enumerate(argv):
    if a == "-oX":
        out = argv[i + 1]

xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
    <hostscript><script id="test-script" output="hello"/></hostscript>
  </host>
</nmaprun>
"""
if out:
    with open(out, "w") as fh:
        fh.write(xml)
print("fake nmap done:", argv[-1])
'''


def _make_config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    script = tmp_path / "fakenmap"
    script.write_text(FAKE_NMAP)
    script.chmod(0o755)
    (config.user_tools_dir / "fakenmap.yaml").write_text(
        f"name: fakenmap\n"
        f"binary: {script}\n"
        f"target: {{mode: append}}\n"
        f"output:\n"
        f"  artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}\n"
        f"  parser: nmap_xml\n"
    )
    return config


async def test_scan_parses_persists_and_browses(tmp_path):
    config = _make_config(tmp_path)
    app = PentuiApp(config=config)
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="recon", includes="10.0.0.0/24", tool="fakenmap")
        assert app.screen.manifest.name == "fakenmap"
        app.screen.query_one("#targets", Input).value = "10.0.0.1"
        await pilot.pause()
        await pilot.click("#run")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()

        status = str(app.screen.query_one("#status", Static).render())
        assert "1 hosts" in status
        assert "1 open ports" in status

        # Persisted into the unified model.
        eng = app.engagement
        hosts = HostRepository(eng.conn).list_for_project(eng.project_id)
        assert [h.ip for h in hosts] == ["10.0.0.1"]
        ports = PortRepository(eng.conn).list_for_host(hosts[0].id)
        assert ports[0].number == 80
        assert ports[0].service.product == "nginx"

        # Results browser shows the host.
        await pilot.press("r")
        await pilot.pause()
        tree = app.screen.query_one("#hosts", Tree)
        labels = [str(node.label) for node in tree.root.children]
        assert any("10.0.0.1" in label for label in labels)
