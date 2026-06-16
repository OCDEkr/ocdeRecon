"""Command-builder and async-runner tests."""

from __future__ import annotations

import asyncio
import sys

import pytest

from pentui.core.executor import (
    ExecutorError,
    Process,
    build_argv,
    build_runs,
    preview,
    requires_root,
    run_command,
    terminate_process,
)
from pentui.core.manifest import OptionType, ToolManifest, ToolOption, load_manifest
from pentui.core.registry import PACKAGED_TOOLS_DIR


def _file_input_manifest() -> ToolManifest:
    return ToolManifest(
        name="batch",
        binary="echo",
        options=[
            ToolOption(
                flag="-f", label="file", type=OptionType.VALUE, file_input=True, file_glob="*.xml"
            )
        ],
    )


def test_build_runs_batches_over_directory(tmp_path):
    d = tmp_path / "scans"
    d.mkdir()
    (d / "a.xml").write_text("a")
    (d / "b.xml").write_text("b")
    (d / "skip.txt").write_text("c")
    runs = build_runs(_file_input_manifest(), options={"-f": str(d)})
    assert [label for label, _ in runs] == ["a.xml", "b.xml"]  # *.xml only, sorted
    first = runs[0][1]
    assert first[first.index("-f") + 1].endswith("a.xml")


def test_build_runs_single_for_a_file(tmp_path):
    f = tmp_path / "a.xml"
    f.write_text("x")
    runs = build_runs(_file_input_manifest(), options={"-f": str(f)})
    assert len(runs) == 1
    assert runs[0][0] == ""


def test_build_runs_single_without_file_input():
    runs = build_runs(ToolManifest(name="t", binary="echo"), targets=["x"])
    assert len(runs) == 1 and runs[0][0] == ""


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
    # artifact flag + resolved path present; the XML is named after the targets
    # ({name}), not a generic "nmap.xml".
    assert "-oX" in argv
    assert str(tmp_path / "10.0.0.1_and_1_more.xml") in argv
    # targets trail
    assert argv[-2:] == ["10.0.0.1", "10.0.0.2"]


def test_build_argv_names_artifact_after_single_target(nmap, tmp_path):
    # A single CIDR target slugifies into a readable, filesystem-safe XML name.
    argv = build_argv(nmap, targets=["192.168.10.0/24"], scan_dir=tmp_path)
    assert str(tmp_path / "192.168.10.0_24.xml") in argv


def test_build_argv_option_types(nmap, tmp_path):
    argv = build_argv(
        nmap,
        options={"-sV": True, "-sS": False, "-p": "22,80", "-T": "5"},
        targets=["scanme.example"],
        scan_dir=tmp_path,
    )
    assert "-sV" in argv  # bool enabled
    assert "-sS" not in argv  # bool disabled
    assert argv[argv.index("-p") : argv.index("-p") + 2] == ["-p", "22,80"]  # value, separate
    assert "-T5" in argv  # choice, attached


def test_build_argv_extra_args(nmap, tmp_path):
    argv = build_argv(
        nmap,
        options={"-sV": True},
        extra_args=["--top-ports", "100"],
        targets=["x"],
        scan_dir=tmp_path,
    )
    assert argv[argv.index("--top-ports") : argv.index("--top-ports") + 2] == ["--top-ports", "100"]
    # extra args land after options but before the artifact flag and targets
    assert argv.index("-sV") < argv.index("--top-ports") < argv.index("-oX")
    assert argv[-1] == "x"


def test_build_argv_sudo_prefix(nmap, tmp_path):
    argv = build_argv(nmap, options={"-sS": True}, targets=["x"], scan_dir=tmp_path, sudo=True)
    # sudo -S reads the password from stdin (no TTY needed)
    assert argv[:4] == ["sudo", "-S", "-p", ""]
    assert argv[4] == "nmap"


def test_build_argv_flag_each_target_mode():
    from pentui.core.manifest import TargetMode, TargetSpec

    manifest = ToolManifest(
        name="sub", binary="sublist3r", target=TargetSpec(mode=TargetMode.FLAG_EACH, flag="-d")
    )
    argv = build_argv(manifest, targets=["a.com", "b.com"])
    # each target inline as `-d <target>` (no targets file)
    assert argv == ["sublist3r", "-d", "a.com", "-d", "b.com"]


def test_flag_each_requires_a_flag():
    from pentui.core.manifest import TargetMode, TargetSpec

    with pytest.raises(ValueError, match="requires a 'flag'"):
        TargetSpec(mode=TargetMode.FLAG_EACH)


def test_build_argv_rejects_bad_port(nmap, tmp_path):
    with pytest.raises(ExecutorError):
        build_argv(nmap, options={"-p": "99999"}, targets=["x"], scan_dir=tmp_path)


def test_build_argv_rejects_bad_choice(nmap, tmp_path):
    with pytest.raises(ExecutorError):
        build_argv(nmap, options={"-T": "9"}, targets=["x"], scan_dir=tmp_path)


def test_gowitness_v3_nmap_command():
    g = load_manifest(PACKAGED_TOOLS_DIR / "gowitness.yaml")
    argv = build_argv(
        g,
        profile=g.profile("Scan from nmap XML"),
        options={
            "-f": "nmap.xml",
            "--write-screenshots": True,
            "--log-scan-errors": True,
            "--open-only": True,
            "--write-db": True,
            "--threads": "16",
            "--timeout": "15",
        },
    )
    assert argv[:3] == ["gowitness", "scan", "nmap"]
    assert argv[argv.index("-f") + 1] == "nmap.xml"
    assert {"--write-screenshots", "--log-scan-errors", "--open-only", "--write-db"} <= set(argv)
    assert argv[argv.index("--threads") + 1] == "16"


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


async def test_run_command_feeds_stdin_data():
    lines: list[str] = []
    result = await run_command(
        [sys.executable, "-c", "import sys; print('got:', sys.stdin.readline().strip())"],
        on_line=lines.append,
        stdin_data="s3cret",
    )
    assert result.exit_code == 0
    assert lines == ["got: s3cret"]


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
