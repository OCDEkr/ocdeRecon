"""End-to-end: the engagement-wide exclude file is written once per run and
injected as ``--excludefile`` into runs of tools that declare an ``exclude_flag``.

This is the second line of defence behind scope filtering: a per-/24 fan-out scans
a whole in-scope CIDR, so excluded IPs sitting inside it would be swept without the
exclude file. Uses a fake nmap so no real tool is needed; assertions read the
persisted scan argv rather than the process output.
"""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.models import ScopeKind
from pentui.core.registry import ToolRegistry
from pentui.core.workflow import WorkflowDefinition, WorkflowEngine, build_workflow_registry
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import (
    ScanRepository,
    ScopeRuleRepository,
    TargetRepository,
)

# Fake nmap: one live host, so the run succeeds and persists its argv.
FAKE_NMAP = """#!/usr/bin/env python3
import sys
out = None
for i, a in enumerate(sys.argv):
    if a == "-oX":
        out = sys.argv[i + 1]
xml = ('<?xml version="1.0"?><nmaprun><host><status state="up"/>'
       '<address addr="10.0.0.5" addrtype="ipv4"/></host></nmaprun>')
if out:
    open(out, "w").write(xml)
print("fake nmap done")
"""


def _setup(tmp_path: Path, *, with_exclude_flag: bool):
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    nmap = tmp_path / "fakenmap"
    nmap.write_text(FAKE_NMAP)
    nmap.chmod(0o755)

    tools = tmp_path / "tools"
    tools.mkdir()
    exclude_line = "exclude_flag: '--excludefile'\n" if with_exclude_flag else ""
    (tools / "nmap.yaml").write_text(
        f"name: nmap\nbinary: {nmap}\ntarget: {{mode: append}}\n{exclude_line}"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
    )
    registry = ToolRegistry()
    registry.load_dir(tools)
    return config, registry, open_engagement(config, "wf")


_WF = WorkflowDefinition.model_validate(
    {
        "name": "scan-only",
        "defaults": {"gates": False},
        "steps": [{"id": "scan", "tool": "nmap", "targets": {"from": "project"}}],
    }
)


def _scope(eng) -> list:
    return ScopeRuleRepository(eng.conn).list_for_project(eng.project_id)


def _nmap_args(eng) -> list[str]:
    scans = ScanRepository(eng.conn).list_recent(eng.project_id)
    assert len(scans) == 1
    return scans[0].args


async def test_exclude_file_written_and_injected(tmp_path):
    config, registry, eng = _setup(tmp_path, with_exclude_flag=True)
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.5")
    rules = ScopeRuleRepository(eng.conn)
    rules.create(eng.project_id, "10.0.0.0/24", ScopeKind.INCLUDE)
    rules.create(eng.project_id, "10.0.0.50", ScopeKind.EXCLUDE)

    await WorkflowEngine(eng, registry, config, scope_rules=_scope(eng), unattended=True).run(_WF)

    # The engagement-wide exclude file holds the excluded value.
    exclude_file = config.engagement_exclude_file("wf")
    assert exclude_file.read_text().split() == ["10.0.0.50"]

    # … and it rides into the nmap argv as `--excludefile <path>`.
    args = _nmap_args(eng)
    assert "--excludefile" in args
    assert args[args.index("--excludefile") + 1] == str(exclude_file)


async def test_no_exclude_rules_means_no_file_and_no_flag(tmp_path):
    config, registry, eng = _setup(tmp_path, with_exclude_flag=True)
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.5")
    ScopeRuleRepository(eng.conn).create(eng.project_id, "10.0.0.0/24", ScopeKind.INCLUDE)

    await WorkflowEngine(eng, registry, config, scope_rules=_scope(eng), unattended=True).run(_WF)

    assert not config.engagement_exclude_file("wf").exists()
    assert "--excludefile" not in _nmap_args(eng)


async def test_tool_without_exclude_flag_is_not_injected(tmp_path):
    # Same excluded scope, but the manifest declares no exclude_flag.
    config, registry, eng = _setup(tmp_path, with_exclude_flag=False)
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.5")
    rules = ScopeRuleRepository(eng.conn)
    rules.create(eng.project_id, "10.0.0.0/24", ScopeKind.INCLUDE)
    rules.create(eng.project_id, "10.0.0.50", ScopeKind.EXCLUDE)

    await WorkflowEngine(eng, registry, config, scope_rules=_scope(eng), unattended=True).run(_WF)

    # The file is still materialized for the run, but no flag is injected.
    assert config.engagement_exclude_file("wf").read_text().split() == ["10.0.0.50"]
    assert "--excludefile" not in _nmap_args(eng)


def test_shipped_engagement_recon_workflow_is_valid():
    wf = build_workflow_registry().get("engagement-recon")
    assert wf is not None
    assert [s.id for s in wf.steps] == [
        "discover",
        "scan",
        "shots",
        "dc-identify",
        "smb-sweep",
        "relay",
    ]
    # One masscan + one nmap; downstream branches all hang off the single nmap scan.
    assert wf.steps[0].tool == "masscan"
    scan = wf.steps[1]
    assert scan.tool == "nmap" and scan.foreach == "subnet/24" and scan.foreach_target == "subnet"
    assert [s.tool for s in wf.steps].count("nmap") == 1
    shots = next(s for s in wf.steps if s.id == "shots")
    assert shots.file_from is not None and shots.file_from.step == "scan"
    for sid in ("dc-identify", "smb-sweep"):
        step = next(s for s in wf.steps if s.id == sid)
        assert step.after == ["scan"] and step.input is not None
    relay = next(s for s in wf.steps if s.id == "relay")
    assert relay.gate is True and relay.after == ["smb-sweep"]
