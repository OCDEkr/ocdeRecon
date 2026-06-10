"""B1: a stdout-only parser (no artifact) receives the run's captured output.

Before the fix the engine passed ``ParseContext.raw_stdout=""``, so a parser for
a tool that writes no artifact (e.g. runfinger) saw nothing. This proves the
streamed stdout is now read back from the scan's log and handed to the parser.
"""

from __future__ import annotations

from pentui.config import AppConfig
from pentui.core.models import Host, ScanResult
from pentui.core.registry import ToolRegistry
from pentui.core.workflow import WorkflowDefinition, WorkflowEngine
from pentui.parsers import _PARSERS
from pentui.parsers.base import ParseContext
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import HostRepository, TargetRepository


async def test_stdout_only_parser_gets_raw_output(tmp_path, monkeypatch):
    config = AppConfig(data_dir=tmp_path / "d", config_dir=tmp_path / "c")
    config.ensure_dirs()
    tools = tmp_path / "tools"
    tools.mkdir()
    # echo as a stand-in tool: a parser, but NO artifact -> parser must use stdout.
    (tools / "grepper.yaml").write_text(
        "name: grepper\nbinary: echo\ntarget: {mode: append}\noutput: {parser: capture}\n"
    )
    registry = ToolRegistry()
    registry.load_dir(tools)
    eng = open_engagement(config, "wf")
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.9")

    captured: dict[str, str] = {}

    def fake_parse(ctx: ParseContext) -> ScanResult:
        captured["stdout"] = ctx.raw_stdout
        return ScanResult(hosts=[Host(ip="10.0.0.9")])

    monkeypatch.setitem(_PARSERS, "capture", fake_parse)

    wf = WorkflowDefinition.model_validate(
        {"name": "x", "steps": [{"id": "s", "tool": "grepper", "targets": {"from": "project"}}]}
    )
    await WorkflowEngine(eng, registry, config, unattended=True).run(wf)

    assert captured["stdout"].strip() == "10.0.0.9"  # echo printed the target
    hosts = HostRepository(eng.conn).list_for_project(eng.project_id)
    assert [h.ip for h in hosts] == ["10.0.0.9"]
