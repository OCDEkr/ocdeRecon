"""End-to-end: discover -> dc-discovery tags LDAP responders as domain controllers.

Uses fake nmap / nxc binaries so no real tools are needed. Proves the D2 handoff:
nxc's LDAP identification lands on host.is_dc, queryable by downstream AD steps.
"""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.query import Materializer, QuerySpec, WhereSpec, run_query
from pentui.core.registry import ToolRegistry
from pentui.core.workflow import WorkflowDefinition, WorkflowEngine, build_workflow_registry
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import HostRepository, TargetRepository

# Fake nmap: two hosts, both tcp/389 open (so both get fed to dc-discovery).
FAKE_NMAP = '''#!/usr/bin/env python3
import sys
out = None
for i, a in enumerate(sys.argv):
    if a == "-oX":
        out = sys.argv[i + 1]
host = """<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="389"><state state="open" reason="syn-ack"/>
<service name="ldap"/></port></ports></host>"""
body = host.format(ip="10.0.0.10") + host.format(ip="10.0.0.11")
xml = '<?xml version="1.0"?><nmaprun>' + body + "</nmaprun>"
if out:
    open(out, "w").write(xml)
print("fake nmap done")
'''

# Fake nxc ldap: only 10.0.0.10 answers with an identification banner (it's the DC).
FAKE_NXC = """#!/usr/bin/env python3
import sys
print("LDAP  10.0.0.10  389  DC01  [*] Windows Server 2019 (name:DC01) (domain:corp.local)")
print("LDAP  10.0.0.11  389  [-] connection refused")
"""


def _setup(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    nmap = tmp_path / "fakenmap"
    nmap.write_text(FAKE_NMAP)
    nmap.chmod(0o755)
    nxc = tmp_path / "fakenxc"
    nxc.write_text(FAKE_NXC)
    nxc.chmod(0o755)

    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "nmap.yaml").write_text(
        f"name: nmap\nbinary: {nmap}\ntarget: {{mode: append}}\n"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
    )
    (tools / "dc-discovery.yaml").write_text(
        f"name: dc-discovery\nbinary: {nxc}\ntarget: {{mode: append}}\n"
        f"output: {{parser: nxc_ldap}}\nprofiles:\n  - {{name: Identify, args: ['ldap']}}\n"
    )
    registry = ToolRegistry()
    registry.load_dir(tools)
    return config, registry, open_engagement(config, "wf")


async def test_dc_discovery_tags_domain_controllers(tmp_path):
    config, registry, eng = _setup(tmp_path)
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.0/24")

    wf = WorkflowDefinition.model_validate(
        {
            "name": "dc",
            "steps": [
                {"id": "discover", "tool": "nmap", "targets": {"from": "project"}},
                {
                    "id": "identify",
                    "tool": "dc-discovery",
                    "profile": "Identify",
                    "after": ["discover"],
                    "input": {"from": "hosts", "where": {"port_open_in": [389]}, "as": "ip_list"},
                },
            ],
        }
    )
    await WorkflowEngine(eng, registry, config, unattended=True).run(wf)

    by_ip = {h.ip: h for h in HostRepository(eng.conn).list_for_project(eng.project_id)}
    assert by_ip["10.0.0.10"].is_dc is True
    assert by_ip["10.0.0.10"].hostname == "DC01"
    assert by_ip["10.0.0.11"].is_dc is None  # answered no banner -> not tagged

    # Downstream AD steps can now select the DCs.
    dcs = run_query(
        eng.conn,
        eng.project_id,
        QuerySpec(where=WhereSpec(is_dc=True), **{"as": Materializer.IP_LIST}),
    )
    assert dcs == ["10.0.0.10"]


def test_shipped_dc_discovery_workflow_is_valid():
    wf = build_workflow_registry().get("dc-discovery")
    assert wf is not None
    assert [s.id for s in wf.steps] == ["discover", "identify"]
    identify = wf.steps[-1]
    assert identify.tool == "dc-discovery" and identify.profile == "Identify"
