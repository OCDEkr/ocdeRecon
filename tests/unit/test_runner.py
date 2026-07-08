"""Unit tests for the tool-runner seam (process today, REST in a later phase)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pentui.core.executor import ExecutorError
from pentui.core.manifest import OutputSpec, ToolKind, ToolManifest
from pentui.core.runner import ProcessRunner, RunRequest, get_runner


def _req(tmp_path: Path) -> RunRequest:
    return RunRequest(
        manifest=ToolManifest(name="echo", binary="echo"),
        profile=None,
        options={},
        extra_args=[],
        targets=["hello", "world"],
        scan_dir=tmp_path / "scan",
        sudo=False,
    )


def test_get_runner_returns_process_runner_by_default():
    assert isinstance(get_runner(ToolManifest(name="echo", binary="echo")), ProcessRunner)


def test_get_runner_rest_requires_config():
    # REST tools need app config (for connection settings); without it, error.
    rest = ToolManifest(name="nessus", binary="nessus", kind=ToolKind.REST)
    with pytest.raises(ExecutorError):
        get_runner(rest)


def test_process_runner_prepare_builds_command(tmp_path):
    plan = ProcessRunner().prepare(_req(tmp_path))
    assert plan.args[0] == "echo"
    assert plan.args[-2:] == ["hello", "world"]
    assert plan.command_str == "echo hello world"
    assert plan.artifact_path is None  # echo declares no artifact


async def test_process_runner_execute_streams_and_logs(tmp_path):
    runner = ProcessRunner()
    req = _req(tmp_path)
    plan = runner.prepare(req)
    lines: list[str] = []
    markers: list[str] = []

    result = await runner.execute(req, plan, on_line=lines.append, on_marker=markers.append)

    assert result.ok and result.exit_code == 0
    assert lines == ["hello world"]  # raw output streamed to on_line
    assert result.raw_output_path is not None
    assert Path(result.raw_output_path).read_text() == "hello world\n"  # teed to stdout.log
    assert any(m.startswith("$ echo") for m in markers)  # command echoed as a marker


async def test_dir_output_tool_runs_in_its_scan_folder(tmp_path):
    # A dir_output tool (e.g. gowitness) writes its store relative to the cwd, so
    # the runner must launch it inside the scan folder — not pentui's own cwd.
    script = tmp_path / "makefile.sh"
    script.write_text("#!/usr/bin/env bash\ntouch made-here.txt\n")
    script.chmod(0o755)
    scan_dir = tmp_path / "scans" / "shots" / "run"
    req = RunRequest(
        manifest=ToolManifest(name="shots", binary=str(script), output=OutputSpec(dir_output=True)),
        profile=None,
        options={},
        extra_args=[],
        targets=[],
        scan_dir=scan_dir,
        sudo=False,
    )
    runner = ProcessRunner()
    plan = runner.prepare(req)
    result = await runner.execute(req, plan, on_line=lambda _l: None, on_marker=lambda _m: None)

    assert result.ok
    # The relative file the tool created lands in the scan folder, not the cwd.
    assert (scan_dir / "made-here.txt").exists()
