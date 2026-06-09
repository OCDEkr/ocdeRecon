"""Unit tests for the tool-runner seam (process today, REST in a later phase)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pentui.core.manifest import ToolKind, ToolManifest
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


def test_get_runner_rejects_rest_until_phase_c():
    rest = ToolManifest(name="nessus", binary="nessus", kind=ToolKind.REST)
    with pytest.raises(NotImplementedError):
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
