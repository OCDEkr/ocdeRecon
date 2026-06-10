"""End-to-end: discover -> nxc smb -> only signing-disabled hosts get relayed.

Uses fake nmap / nxc / relay binaries so no real tools are needed. Proves the
handoff: the nxc-smb signing state lands on host.smb_signing, and the relay step's
query (smb_signing_in: ["disabled"]) materialises an ip_list that is written to the
relay tool's target file — i.e. only unsigned hosts are staged.
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

# Fake nxc smb: prints an nxc-style banner per positional IP target (target.mode
# append), marking .1 signing:False (disabled), others signing:True (required).
FAKE_NXC = r"""#!/usr/bin/env python3
import re, sys
ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
for a in sys.argv[1:]:
    if ip_re.match(a):
        signing = "False" if a.endswith(".1") else "True"
        print("SMB  %s  445  HOST  [*] Windows (name:HOST) (signing:%s)" % (a, signing))
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
    (tools / "smb-enum.yaml").write_text(
        f"name: smb-enum\nbinary: {nxc}\ntarget: {{mode: append}}\noutput: {{parser: nxc_smb}}\n"
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
                    "tool": "smb-enum",
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

    # nxc smb recorded each host's signing state on the unified model.
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
    assert wf.steps[1].tool == "smb-enum"
    relay = wf.steps[-1]
    assert relay.tool == "ntlmrelayx" and relay.gate is True
    assert relay.input is not None and relay.input.where.smb_signing_in == ["disabled"]
