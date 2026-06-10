"""End-to-end: discover -> runfinger -> only signing-disabled hosts get relayed.

Uses fake nmap / runfinger / relay binaries so no real tools are needed. Proves
the D1 handoff: runfinger's signing state lands on host.smb_signing, and the
relay step's query (smb_signing_in: ["disabled"]) materialises an ip_list that is
written to the relay tool's target file — i.e. only unsigned hosts are staged.
"""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.registry import ToolRegistry
from pentui.core.workflow import WorkflowDefinition, WorkflowEngine, build_workflow_registry
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import HostRepository, TargetRepository

# Fake nmap: two hosts, both tcp/445 open.
FAKE_NMAP = '''#!/usr/bin/env python3
import sys
out = None
for i, a in enumerate(sys.argv):
    if a == "-oX":
        out = sys.argv[i + 1]
host = """<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/>
<service name="microsoft-ds"/></port></ports></host>"""
body = host.format(ip="10.0.0.1") + host.format(ip="10.0.0.2")
xml = '<?xml version="1.0"?><nmaprun>' + body + "</nmaprun>"
if out:
    open(out, "w").write(xml)
print("fake nmap done")
'''

# Fake runfinger: reads the -f host file and marks .1 disabled, others required.
FAKE_RUNFINGER = """#!/usr/bin/env python3
import sys
path = None
for i, a in enumerate(sys.argv):
    if a == "-f":
        path = sys.argv[i + 1]
hosts = open(path).read().split() if path else []
for ip in hosts:
    signing = "False" if ip.endswith(".1") else "True"
    print("['%s', Os:'Windows', Signing:'%s']" % (ip, signing))
"""


def _setup(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    nmap = tmp_path / "fakenmap"
    nmap.write_text(FAKE_NMAP)
    nmap.chmod(0o755)
    finger = tmp_path / "fakefinger"
    finger.write_text(FAKE_RUNFINGER)
    finger.chmod(0o755)

    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "nmap.yaml").write_text(
        f"name: nmap\nbinary: {nmap}\ntarget: {{mode: append}}\n"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
    )
    (tools / "runfinger.yaml").write_text(
        f"name: runfinger\nbinary: {finger}\ntarget: {{mode: flag, flag: '-f'}}\n"
        f"output: {{parser: runfinger}}\n"
    )
    # Fake relay tool: echo, but with ntlmrelayx's -tf target-file mode so we can
    # read back exactly which hosts were staged for relay.
    (tools / "relay.yaml").write_text(
        "name: relay\nbinary: echo\ntarget: {mode: flag, flag: '-tf'}\n"
    )
    registry = ToolRegistry()
    registry.load_dir(tools)
    return config, registry, open_engagement(config, "wf")


async def test_only_unsigned_hosts_are_staged_for_relay(tmp_path):
    config, registry, eng = _setup(tmp_path)
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.0/24")

    wf = WorkflowDefinition.model_validate(
        {
            "name": "unsigned",
            "defaults": {"gates": False},
            "steps": [
                {"id": "discover", "tool": "nmap", "targets": {"from": "project"}},
                {
                    "id": "finger",
                    "tool": "runfinger",
                    "after": ["discover"],
                    "input": {"from": "hosts", "where": {"port_open_in": [445]}, "as": "ip_list"},
                },
                {
                    "id": "relay",
                    "tool": "relay",
                    "after": ["finger"],
                    "input": {
                        "from": "hosts",
                        "where": {"smb_signing_in": ["disabled"]},
                        "as": "ip_list",
                    },
                },
            ],
        }
    )
    await WorkflowEngine(eng, registry, config, unattended=True).run(wf)

    # runfinger recorded each host's signing state on the unified model.
    signing = {
        h.ip: h.smb_signing for h in HostRepository(eng.conn).list_for_project(eng.project_id)
    }
    assert signing == {"10.0.0.1": "disabled", "10.0.0.2": "required"}

    # The relay step's target file holds only the signing-disabled host.
    relay_targets = [
        p for p in config.engagement_dir("wf").rglob("targets.txt") if "/relay/" in str(p)
    ]
    assert len(relay_targets) == 1
    assert relay_targets[0].read_text().split() == ["10.0.0.1"]


def test_shipped_unsigned_relay_workflow_is_valid():
    wf = build_workflow_registry().get("unsigned-relay")
    assert wf is not None
    assert [s.id for s in wf.steps] == ["discover", "finger", "relay"]
    relay = wf.steps[-1]
    assert relay.tool == "ntlmrelayx" and relay.gate is True
    assert relay.input is not None and relay.input.where.smb_signing_in == ["disabled"]
