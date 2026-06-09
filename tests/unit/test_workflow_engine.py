"""Workflow engine end-to-end tests using fake tools (no real nmap needed).

Proves the headline capability: one tool's output feeds the next automatically.
"""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.models import Host, ScopeKind, ScopeRule
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


FAKE_SHOT = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "f = None\n"
    "for i, a in enumerate(sys.argv):\n"
    "    if a == '-f':\n"
    "        f = sys.argv[i + 1]\n"
    "print('shot', f)\n"
)


def _fanout_setup(tmp_path: Path):
    config, registry, eng = _setup(tmp_path)
    # add a fakeshot tool with a file_input -f (batches over a directory)
    shot = tmp_path / "fakeshot"
    shot.write_text(FAKE_SHOT)
    shot.chmod(0o755)
    (tmp_path / "tools" / "fakeshot.yaml").write_text(
        f"name: fakeshot\nbinary: {shot}\ntarget: {{mode: append}}\noptions:\n"
        f"  - {{flag: '-f', label: in, type: value, file_input: true, file_glob: '*.xml'}}\n"
    )
    registry.load_dir(tmp_path / "tools")
    # hosts across two /24s, all up
    for ip in ("10.0.1.5", "10.0.1.6", "10.0.2.7"):
        HostRepository(eng.conn).upsert(eng.project_id, Host(ip=ip, state="up"))
    return config, registry, eng


async def test_per_subnet_fanout_then_batch_gowitness(tmp_path):
    config, registry, eng = _fanout_setup(tmp_path)
    wf = WorkflowDefinition.model_validate({
        "name": "fanout",
        "steps": [
            {"id": "scan", "tool": "fakenmap", "foreach": "subnet/24",
             "input": {"from": "hosts", "where": {"host_state": "up"}, "as": "targets"}},
            {"id": "shots", "tool": "fakeshot", "after": ["scan"],
             "file_from": {"step": "scan", "flag": "-f"}},
        ],
    })
    run = await WorkflowEngine(eng, registry, config, unattended=True).run(wf)

    assert engine_states_done(eng, run)

    # nmap ran once per /24, each XML collected into the step's artifact dir.
    artifacts = config.workflow_artifacts_dir(eng.name, run.id, "scan")
    collected = sorted(p.name for p in artifacts.glob("*.xml"))
    assert collected == ["10.0.1.0_24.xml", "10.0.2.0_24.xml"]

    # gowitness (fakeshot) batched once per collected file.
    steps = {s.step_id: s for s in StepRunRepository(eng.conn).list_for_run(run.id)}
    shots_log = (config.scan_dir(eng.name, steps["shots"].scan_id) / "stdout.log").read_text()
    assert "10.0.1.0_24.xml" in shots_log and "10.0.2.0_24.xml" in shots_log


def engine_states_done(eng, run) -> bool:
    steps = StepRunRepository(eng.conn).list_for_run(run.id)
    return all(s.status.value == "done" for s in steps) and len(steps) == 2


# A tool that records peak simultaneity: it drops a marker, sleeps, then counts
# how many markers exist at once (after the sleep, so every concurrently-admitted
# run is present) and writes that count out. max(counts) == observed parallelism.
FAKE_CONC_TMPL = """#!/usr/bin/env python3
import glob, os, sys, time
run_dir, peak_dir = {run_dir!r}, {peak_dir!r}
me = os.path.join(run_dir, str(os.getpid()))
open(me, "w").close()
time.sleep(0.3)
n = len(glob.glob(os.path.join(run_dir, "*")))
open(os.path.join(peak_dir, str(os.getpid())), "w").write(str(n))
os.remove(me)
print("conc", sys.argv[-1])
"""


def _conc_setup(tmp_path: Path, *, subnets: int):
    config, registry, eng = _setup(tmp_path)
    run_dir = tmp_path / "conc_run"
    peak_dir = tmp_path / "conc_peak"
    run_dir.mkdir()
    peak_dir.mkdir()
    script = tmp_path / "fakeconc"
    script.write_text(FAKE_CONC_TMPL.format(run_dir=str(run_dir), peak_dir=str(peak_dir)))
    script.chmod(0o755)
    (tmp_path / "tools" / "fakeconc.yaml").write_text(
        f"name: fakeconc\nbinary: {script}\ntarget: {{mode: append}}\n"
    )
    registry.load_dir(tmp_path / "tools")
    # One up host in each of `subnets` distinct /24s -> one foreach group each.
    for i in range(subnets):
        HostRepository(eng.conn).upsert(eng.project_id, Host(ip=f"10.0.{i}.5", state="up"))
    return config, registry, eng, peak_dir


def _conc_wf(*, max_parallel: int | None = None) -> WorkflowDefinition:
    defaults = {"max_parallel": max_parallel} if max_parallel is not None else {}
    return WorkflowDefinition.model_validate({
        "name": "conc",
        "defaults": defaults,
        "steps": [
            {"id": "scan", "tool": "fakeconc", "foreach": "subnet/24",
             "input": {"from": "hosts", "where": {"host_state": "up"}, "as": "targets"}},
        ],
    })


def _peak(peak_dir: Path) -> int:
    return max((int(p.read_text()) for p in peak_dir.iterdir()), default=0)


async def test_foreach_fanout_runs_in_parallel(tmp_path):
    config, registry, eng, peak_dir = _conc_setup(tmp_path, subnets=3)
    config.max_concurrent_scans = 4
    await WorkflowEngine(eng, registry, config, unattended=True).run(_conc_wf())
    assert _peak(peak_dir) == 3  # all three /24s overlapped


async def test_foreach_fanout_is_bounded_by_config(tmp_path):
    config, registry, eng, peak_dir = _conc_setup(tmp_path, subnets=3)
    config.max_concurrent_scans = 2
    await WorkflowEngine(eng, registry, config, unattended=True).run(_conc_wf())
    assert _peak(peak_dir) == 2  # never more than the limit in flight


async def test_workflow_max_parallel_overrides_config(tmp_path):
    config, registry, eng, peak_dir = _conc_setup(tmp_path, subnets=3)
    config.max_concurrent_scans = 4
    await WorkflowEngine(eng, registry, config, unattended=True).run(_conc_wf(max_parallel=1))
    assert _peak(peak_dir) == 1  # workflow caps below the config default


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
