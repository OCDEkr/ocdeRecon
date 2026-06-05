"""Workflow engine end-to-end tests using fake tools (no real nmap needed).

Proves the headline capability: one tool's output feeds the next automatically.
"""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.models import ScopeKind, ScopeRule
from pentui.core.registry import ToolRegistry
from pentui.core.workflow import StepState, WorkflowDefinition, WorkflowEngine, WorkflowStep
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import (
    AuditLogRepository,
    HostRepository,
    StepRunRepository,
    TargetRepository,
)

FAKE_NMAP = '''#!/usr/bin/env python3
import sys
out = None
for i, a in enumerate(sys.argv):
    if a == "-oX":
        out = sys.argv[i + 1]
xml = """<?xml version="1.0"?>
<nmaprun><host>
  <status state="up"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="nginx"/>
  </port></ports>
</host></nmaprun>
"""
if out:
    open(out, "w").write(xml)
print("fake nmap scanned", sys.argv[-1])
'''


def _setup(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    script = tmp_path / "fakenmap"
    script.write_text(FAKE_NMAP)
    script.chmod(0o755)

    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "fakenmap.yaml").write_text(
        f"name: fakenmap\nbinary: {script}\ntarget: {{mode: append}}\n"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
    )
    (tools / "echo.yaml").write_text("name: echo\nbinary: echo\ntarget: {mode: append}\n")
    registry = ToolRegistry()
    registry.load_dir(tools)

    engagement = open_engagement(config, "wf")
    return config, registry, engagement


def _wf(steps: list[dict]) -> WorkflowDefinition:
    return WorkflowDefinition.model_validate({"name": "chain", "steps": steps})


async def test_chain_feeds_one_tool_into_the_next(tmp_path):
    config, registry, eng = _setup(tmp_path)
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.1")

    wf = _wf([
        {"id": "discover", "tool": "fakenmap", "targets": {"from": "project"}},
        {
            "id": "shots", "tool": "echo", "after": ["discover"],
            "input": {"from": "hosts", "where": {"port_open_in": [80]}, "as": "target_urls"},
        },
    ])
    engine = WorkflowEngine(eng, registry, config, unattended=True)
    run = await engine.run(wf)

    # discover persisted the host into the unified model
    hosts = HostRepository(eng.conn).list_for_project(eng.project_id)
    assert [h.ip for h in hosts] == ["10.0.0.1"]

    # both steps completed
    assert engine.states == {"discover": StepState.DONE, "shots": StepState.DONE}

    # the second tool received the URL materialized from the first tool's output
    steps = {s.step_id: s for s in StepRunRepository(eng.conn).list_for_run(run.id)}
    shots_dir = config.scan_dir(eng.name, steps["shots"].scan_id)
    assert (shots_dir / "stdout.log").read_text().strip() == "http://10.0.0.1:80"


async def test_out_of_scope_target_is_skipped_and_logged(tmp_path):
    config, registry, eng = _setup(tmp_path)
    TargetRepository(eng.conn).create(eng.project_id, "8.8.8.8")
    rules = [ScopeRule(project_id=eng.project_id, value="10.0.0.0/24", kind=ScopeKind.INCLUDE)]

    wf = _wf([{"id": "discover", "tool": "fakenmap", "targets": {"from": "project"}}])
    engine = WorkflowEngine(eng, registry, config, scope_rules=rules, unattended=True)
    await engine.run(wf)

    assert engine.states["discover"] is StepState.SKIPPED
    actions = [a for _, a, _ in AuditLogRepository(eng.conn).list_for_project(eng.project_id)]
    assert "scope_skip" in actions


async def test_declined_gate_skips_step_and_descendants(tmp_path):
    config, registry, eng = _setup(tmp_path)
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.1")

    wf = _wf([
        {"id": "first", "tool": "echo", "targets": {"from": "project"}},
        {"id": "gated", "tool": "echo", "after": ["first"], "gate": True,
         "targets": {"from": "project"}},
        {"id": "last", "tool": "echo", "after": ["gated"], "targets": {"from": "project"}},
    ])

    async def deny(step: WorkflowStep) -> bool:
        return False

    engine = WorkflowEngine(eng, registry, config, unattended=False, gate_approver=deny)
    await engine.run(wf)

    assert engine.states["first"] is StepState.DONE
    assert engine.states["gated"] is StepState.SKIPPED
    assert engine.states["last"] is StepState.SKIPPED
