"""Command-builder and async-runner tests."""

from __future__ import annotations

import asyncio
import sys

import pytest

from pentui.core.executor import (
    ExecutorError,
    Process,
    build_argv,
    preview,
    requires_root,
    run_command,
    terminate_process,
)
from pentui.core.manifest import load_manifest
from pentui.core.registry import PACKAGED_TOOLS_DIR


@pytest.fixture
def nmap():
    return load_manifest(PACKAGED_TOOLS_DIR / "nmap.yaml")


def test_build_argv_profile_and_targets(nmap, tmp_path):
    argv = build_argv(
        nmap,
        profile=nmap.profile("Quick"),
        targets=["10.0.0.1", "10.0.0.2"],
        scan_dir=tmp_path,
    )
    assert argv[0] == "nmap"
    assert "-F" in argv  # from the Quick profile
    # artifact flag + resolved path present
    assert "-oX" in argv
    assert str(tmp_path / "nmap.xml") in argv
    # targets trail
    assert argv[-2:] == ["10.0.0.1", "10.0.0.2"]


def test_build_argv_option_types(nmap, tmp_path):
    argv = build_argv(
        nmap,
        options={"-sV": True, "-sS": False, "-p": "22,80", "-T": "5"},
        targets=["scanme.example"],
        scan_dir=tmp_path,
    )
    assert "-sV" in argv          # bool enabled
    assert "-sS" not in argv      # bool disabled
    assert argv[argv.index("-p"):argv.index("-p") + 2] == ["-p", "22,80"]  # value, separate
    assert "-T5" in argv          # choice, attached


def test_build_argv_sudo_prefix(nmap, tmp_path):
    argv = build_argv(nmap, options={"-sS": True}, targets=["x"], scan_dir=tmp_path, sudo=True)
    assert argv[0] == "sudo"
    assert argv[1] == "nmap"


def test_build_argv_rejects_bad_port(nmap, tmp_path):
    with pytest.raises(ExecutorError):
        build_argv(nmap, options={"-p": "99999"}, targets=["x"], scan_dir=tmp_path)


def test_build_argv_rejects_bad_choice(nmap, tmp_path):
    with pytest.raises(ExecutorError):
        build_argv(nmap, options={"-T": "9"}, targets=["x"], scan_dir=tmp_path)


def test_requires_root(nmap):
    assert requires_root(nmap, profile=nmap.profile("Full TCP")) is True
    assert requires_root(nmap, profile=nmap.profile("Quick")) is False
    assert requires_root(nmap, options={"-O": True}) is True
    assert requires_root(nmap, options={"-sV": True}) is False


def test_preview_is_shell_quoted(nmap, tmp_path):
    argv = build_argv(nmap, options={"-p": "22,80"}, targets=["x"], scan_dir=tmp_path)
    assert preview(argv).startswith("nmap ")


async def test_run_command_streams_and_logs(tmp_path):
    lines: list[str] = []
    result = await run_command(
        [sys.executable, "-c", "print('hello'); print('world')"],
        scan_dir=tmp_path,
        on_line=lines.append,
    )
    assert result.exit_code == 0
    assert lines == ["hello", "world"]
    assert (tmp_path / "stdout.log").read_text() == "hello\nworld\n"


async def test_run_command_missing_binary():
    with pytest.raises(ExecutorError):
        await run_command(["pentui-nonexistent-binary-xyz"])


async def test_run_command_nonzero_exit():
    result = await run_command([sys.executable, "-c", "import sys; sys.exit(3)"])
    assert result.exit_code == 3
    assert result.stopped is False


async def test_run_command_can_be_stopped(tmp_path):
    holder: dict[str, Process] = {}
    task = asyncio.create_task(
        run_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            scan_dir=tmp_path,
            on_start=lambda p: holder.setdefault("p", p),
        )
    )
    while "p" not in holder:
        await asyncio.sleep(0.02)
    terminate_process(holder["p"])
    result = await task
    assert result.stopped
    assert result.exit_code < 0


async def test_run_command_cancellation_terminates_process():
    holder: dict[str, Process] = {}
    task = asyncio.create_task(
        run_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            on_start=lambda p: holder.setdefault("p", p),
        )
    )
    while "p" not in holder:
        await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.1)
    assert holder["p"].returncode is not None  # process was killed, not orphaned
