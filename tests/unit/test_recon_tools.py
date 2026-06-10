"""D3/D4: subdomain-recon end-to-end, and the cewl wordlist manifest."""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.executor import build_argv
from pentui.core.manifest import load_manifest
from pentui.core.models import ScanStatus, ScopeKind
from pentui.core.registry import PACKAGED_TOOLS_DIR, ToolRegistry, build_registry
from pentui.core.workflow import WorkflowDefinition, WorkflowEngine, build_workflow_registry
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import (
    HostRepository,
    ScanRepository,
    ScopeRuleRepository,
    TargetRepository,
)

# Fake sublist3r: writes the -o file with two subdomains; ignores its input.
FAKE_SUBLIST3R = """#!/usr/bin/env python3
import sys
out = None
for i, a in enumerate(sys.argv):
    if a == "-o":
        out = sys.argv[i + 1]
if out:
    open(out, "w").write("www.example.com\\nmail.example.com\\n")
print("done")
"""

# Fake nmap: no real XML needed; just records that it ran over its targets.
FAKE_NMAP = """#!/usr/bin/env python3
import sys
print("scanned", " ".join(a for a in sys.argv[1:] if not a.startswith("-")))
"""


def _setup(tmp_path: Path):
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    sub = tmp_path / "fakesub"
    sub.write_text(FAKE_SUBLIST3R)
    sub.chmod(0o755)
    nmap = tmp_path / "fakenmap"
    nmap.write_text(FAKE_NMAP)
    nmap.chmod(0o755)

    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "sublist3r.yaml").write_text(
        f"name: sublist3r\nbinary: {sub}\ntarget: {{mode: flag_each, flag: '-d'}}\n"
        f"output: {{artifact: {{flag: '-o', path: '{{scan_dir}}/subdomains.txt'}}, "
        f"parser: sublist3r}}\n"
    )
    (tools / "nmap.yaml").write_text(
        f"name: nmap\nbinary: {nmap}\ntarget: {{mode: append}}\n"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
        f"profiles:\n  - {{name: 'Service scan', args: ['-sV']}}\n"
    )
    registry = ToolRegistry()
    registry.load_dir(tools)
    return config, registry, open_engagement(config, "wf")


async def test_subdomain_recon_enumerates_then_scans_in_scope(tmp_path):
    config, registry, eng = _setup(tmp_path)
    # Scope the root domain; discovered subdomains must be in scope (suffix match).
    ScopeRuleRepository(eng.conn).create(eng.project_id, "example.com", ScopeKind.INCLUDE)
    TargetRepository(eng.conn).create(eng.project_id, "example.com")
    scope_rules = ScopeRuleRepository(eng.conn).list_for_project(eng.project_id)

    wf = WorkflowDefinition.model_validate(
        {
            "name": "sub",
            "steps": [
                {"id": "enum", "tool": "sublist3r", "targets": {"from": "project"}},
                {
                    "id": "scan",
                    "tool": "nmap",
                    "profile": "Service scan",
                    "after": ["enum"],
                    "input": {"from": "hosts", "where": {"hostname_matches": "."}, "as": "targets"},
                },
            ],
        }
    )
    await WorkflowEngine(eng, registry, config, scope_rules=scope_rules, unattended=True).run(wf)

    # sublist3r recorded the subdomains as hostname-keyed hosts.
    hosts = {h.ip for h in HostRepository(eng.conn).list_for_project(eng.project_id)}
    assert {"www.example.com", "mail.example.com"} <= hosts

    # The nmap step ran (domain-suffix scope let the subdomains through) and
    # targeted both of them — not skipped as out of scope.
    scans = ScanRepository(eng.conn).list_recent(eng.project_id)
    nmap_scan = next(s for s in scans if s.tool == "nmap")
    assert nmap_scan.status is ScanStatus.DONE
    assert "www.example.com" in nmap_scan.command_str
    assert "mail.example.com" in nmap_scan.command_str


def test_cewl_manifest_builds_wordlist_argv(tmp_path):
    cewl = load_manifest(PACKAGED_TOOLS_DIR / "cewl.yaml")
    assert cewl.output.parser is None  # wordlist is an artifact, not parsed
    argv = build_argv(cewl, options={"-d": "3"}, targets=["http://site"], scan_dir=tmp_path)
    assert argv[0] == "cewl"
    assert argv[argv.index("-w") + 1].endswith("wordlist.txt")
    assert argv[-1] == "http://site"  # url passed positionally


def test_shipped_subdomain_recon_workflow_is_valid():
    wf = build_workflow_registry().get("subdomain-recon")
    assert wf is not None
    assert [s.id for s in wf.steps] == ["enum", "scan"]
    assert wf.steps[0].tool == "sublist3r"
    assert build_registry().get("cewl") is not None
