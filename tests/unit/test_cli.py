"""Headless `pentui run-workflow` CLI tests (no TUI)."""

from __future__ import annotations

from pathlib import Path

from pentui.cli import main
from pentui.config import AppConfig
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import HostRepository, TargetRepository

from .test_workflow_engine import FAKE_NMAP


def _prepare(tmp_path: Path, monkeypatch) -> AppConfig:  # noqa: ANN001
    """Point XDG dirs at tmp_path and lay down a fake tool + workflow."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    config = AppConfig()
    config.ensure_dirs()

    script = tmp_path / "fakenmap"
    script.write_text(FAKE_NMAP)
    script.chmod(0o755)
    (config.user_tools_dir / "fakenmap.yaml").write_text(
        f"name: fakenmap\nbinary: {script}\ntarget: {{mode: append}}\n"
        f"output: {{artifact: {{flag: '-oX', path: '{{scan_dir}}/nmap.xml'}}, parser: nmap_xml}}\n"
    )
    (config.user_workflows_dir / "probe.yaml").write_text(
        "name: probe\nsteps:\n  - {id: scan, tool: fakenmap, targets: {from: project}}\n"
    )
    return config


def test_run_workflow_headless_persists_results(tmp_path, monkeypatch, capsys):
    config = _prepare(tmp_path, monkeypatch)
    eng = open_engagement(config, "acme")
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.1")
    eng.conn.close()

    rc = main(["run-workflow", "acme", "probe"])
    assert rc == 0

    out = capsys.readouterr().out
    assert "running workflow 'probe'" in out
    assert "1 ok, 0 errored" in out

    eng2 = open_engagement(config, "acme")
    hosts = HostRepository(eng2.conn).list_for_project(eng2.project_id)
    assert [h.ip for h in hosts] == ["10.0.0.1"]


def test_run_workflow_unknown_workflow_errors(tmp_path, monkeypatch, capsys):
    config = _prepare(tmp_path, monkeypatch)
    open_engagement(config, "acme").conn.close()
    rc = main(["run-workflow", "acme", "ghost"])
    assert rc == 2
    assert "unknown workflow 'ghost'" in capsys.readouterr().err


def test_run_workflow_unknown_engagement_errors(tmp_path, monkeypatch, capsys):
    _prepare(tmp_path, monkeypatch)
    rc = main(["run-workflow", "nope", "probe"])
    assert rc == 2
    assert "engagement 'nope' not found" in capsys.readouterr().err
