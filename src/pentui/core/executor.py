"""Command building + async subprocess execution (PROJECT.md §9).

Commands are built as argv LISTS — never a shell string, never ``shell=True``.
Free-text ``value`` inputs pass through named validators (incl. a baseline
shell-metacharacter check) before reaching argv. Root elevation is decided by the
caller (the TUI/workflow engine, which handle the sudo prompt); this module stays
UI-free and only prepends ``sudo`` when told to.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import signal
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pentui.core.manifest import OptionType, TargetMode, ToolManifest, ToolProfile
from pentui.core.validators import ValidationFailed, validate_value

#: A user's option selections, keyed by option flag.
#: bool options -> True/False; value/choice options -> the string value.
OptionValues = Mapping[str, str | bool]

Process = asyncio.subprocess.Process


class ExecutorError(Exception):
    """Raised when a command cannot be built or launched."""


@dataclass(slots=True)
class CompletedScan:
    argv: list[str]
    exit_code: int
    stdout_log_path: str | None

    @property
    def stopped(self) -> bool:
        """True when the process was killed by a signal (e.g. operator stop)."""
        return self.exit_code < 0


def terminate_process(proc: Process) -> None:
    """Stop a running process and its children (the whole process group).

    Processes are launched in their own session, so signalling the group reaches
    children too (e.g. the tool under ``sudo``). If the group runs as root and we
    can't signal it directly, fall back to ``sudo -n kill`` (cached credentials).
    """
    if proc.returncode is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        with contextlib.suppress(Exception):
            subprocess.run(
                ["sudo", "-n", "kill", "-TERM", "--", f"-{pgid}"],  # noqa: S603,S607
                check=False,
            )


def requires_root(
    manifest: ToolManifest,
    *,
    profile: ToolProfile | None = None,
    options: OptionValues | None = None,
) -> bool:
    """Union of the manifest's, profile's, and any selected option's root flags."""
    if manifest.requires_root:
        return True
    if profile is not None and profile.requires_root:
        return True
    options = options or {}
    for option in manifest.options:
        selected = options.get(option.flag)
        if option.requires_root and selected not in (None, False, ""):
            return True
    return False


def _option_tokens(manifest: ToolManifest, options: OptionValues) -> list[str]:
    tokens: list[str] = []
    by_flag = {opt.flag: opt for opt in manifest.options}
    for flag, raw in options.items():
        option = by_flag.get(flag)
        if option is None:
            raise ExecutorError(f"unknown option flag for {manifest.name!r}: {flag!r}")
        if option.type is OptionType.BOOL:
            if raw:
                tokens.append(flag)
            continue
        if raw in (None, False, ""):
            continue  # value/choice left unset
        value = str(raw)
        if option.type is OptionType.CHOICE and value not in option.choices:
            raise ExecutorError(f"{flag!r}: {value!r} not in {option.choices}")
        if option.type is OptionType.VALUE:
            try:
                value = validate_value(option.validate_with, value)
            except ValidationFailed as exc:
                raise ExecutorError(f"{flag!r}: {exc}") from exc
        if option.attached:
            tokens.append(f"{flag}{value}")
        else:
            tokens.extend([flag, value])
    return tokens


def build_argv(
    manifest: ToolManifest,
    *,
    profile: ToolProfile | None = None,
    options: OptionValues | None = None,
    extra_args: Sequence[str] | None = None,
    targets: Sequence[str] | None = None,
    scan_dir: str | Path | None = None,
    sudo: bool = False,
) -> list[str]:
    """Assemble the argv for a tool run. ``sudo`` is prepended only if requested.

    Order: ``[sudo] binary <profile args> <option tokens> <extra_args>
    <artifact flags> <targets>``. ``extra_args`` are operator-authored raw tokens.
    """
    argv: list[str] = ["sudo"] if sudo else []
    argv.append(manifest.binary)

    if profile is not None:
        argv.extend(profile.args)

    argv.extend(_option_tokens(manifest, options or {}))

    if extra_args:
        argv.extend(extra_args)

    artifact = manifest.output.artifact
    if artifact is not None:
        if scan_dir is None:
            raise ExecutorError(f"{manifest.name!r} produces an artifact but no scan_dir given")
        argv.extend([artifact.flag, artifact.path.format(scan_dir=str(scan_dir))])

    targets = list(targets or [])
    if targets:
        if manifest.target.mode is TargetMode.APPEND:
            argv.extend(targets)
        else:  # TargetMode.FLAG — write a target file and pass it
            if scan_dir is None:
                raise ExecutorError("target.mode 'flag' requires a scan_dir for the target file")
            target_file = Path(scan_dir) / "targets.txt"
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text("\n".join(targets) + "\n")
            assert manifest.target.flag is not None  # guaranteed by TargetSpec validation
            argv.extend([manifest.target.flag, str(target_file)])

    return argv


def file_input_batch(manifest: ToolManifest, options: OptionValues) -> list[Path] | None:
    """Files to batch over, or None if this run isn't a directory batch.

    Returns the matching files when a ``file_input`` option points at a directory
    (sorted); ``None`` when no file-input option is a directory (a single run).
    """
    option = next((o for o in manifest.options if o.file_input), None)
    if option is None:
        return None
    value = options.get(option.flag)
    if not isinstance(value, str) or not value or not Path(value).is_dir():
        return None
    return [p for p in sorted(Path(value).glob(option.file_glob)) if p.is_file()]


def build_runs(
    manifest: ToolManifest,
    *,
    profile: ToolProfile | None = None,
    options: OptionValues | None = None,
    extra_args: Sequence[str] | None = None,
    targets: Sequence[str] | None = None,
    scan_dir: str | Path | None = None,
    sudo: bool = False,
) -> list[tuple[str, list[str]]]:
    """Build the argv(s) for a run as ``(label, argv)`` pairs.

    A single ``("", argv)`` normally; one entry per file (labelled by file name)
    when a ``file_input`` option points at a directory (batch-over-directory).
    """
    options = dict(options or {})
    batch = file_input_batch(manifest, options)
    if batch is not None:
        option = next(o for o in manifest.options if o.file_input)
        runs: list[tuple[str, list[str]]] = []
        for path in batch:
            argv = build_argv(
                manifest, profile=profile, options={**options, option.flag: str(path)},
                extra_args=extra_args, targets=targets, scan_dir=scan_dir, sudo=sudo,
            )
            runs.append((path.name, argv))
        return runs
    argv = build_argv(
        manifest, profile=profile, options=options, extra_args=extra_args,
        targets=targets, scan_dir=scan_dir, sudo=sudo,
    )
    return [("", argv)]


def config_tokens(
    manifest: ToolManifest,
    *,
    profile: ToolProfile | None = None,
    options: OptionValues | None = None,
    extra_args: Sequence[str] | None = None,
) -> list[str]:
    """The configuration tokens for a run — profile args + options + extra args.

    Excludes the binary, artifact flags, targets, and sudo, so the result is
    suitable for saving as a reusable profile's ``args``.
    """
    tokens = list(profile.args) if profile is not None else []
    tokens.extend(_option_tokens(manifest, options or {}))
    if extra_args:
        tokens.extend(extra_args)
    return tokens


def preview(argv: Sequence[str]) -> str:
    """Human-readable command line for display (not for execution)."""
    return shlex.join(argv)


async def run_command(
    argv: Sequence[str],
    *,
    scan_dir: str | Path | None = None,
    on_line: Callable[[str], None] | None = None,
    on_start: Callable[[Process], None] | None = None,
    env: Mapping[str, str] | None = None,
) -> CompletedScan:
    """Run ``argv``, streaming merged stdout+stderr line-by-line.

    Each line is passed to ``on_line`` (if given) and teed to
    ``<scan_dir>/stdout.log`` (if ``scan_dir`` given). ``on_start`` receives the
    process so a caller can stop it (see ``terminate_process``). The process runs
    in its own session so stopping it reaches child processes. Returns on exit;
    if the awaiting task is cancelled, the process is terminated first.
    """
    argv = list(argv)
    log_path: Path | None = None
    log_handle = None
    if scan_dir is not None:
        scan_path = Path(scan_dir)
        scan_path.mkdir(parents=True, exist_ok=True)
        log_path = scan_path / "stdout.log"
        log_handle = log_path.open("w", encoding="utf-8")

    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, **env} if env else None,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise ExecutorError(f"command not found: {argv[0]!r}") from exc

        if on_start is not None:
            on_start(proc)

        assert proc.stdout is not None
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                line = raw.decode(errors="replace").rstrip("\n")
                if on_line is not None:
                    on_line(line)
                if log_handle is not None:
                    log_handle.write(line + "\n")
            exit_code = await proc.wait()
        except asyncio.CancelledError:
            terminate_process(proc)
            with contextlib.suppress(Exception):
                await proc.wait()
            raise
    finally:
        if log_handle is not None:
            log_handle.close()

    return CompletedScan(
        argv=argv,
        exit_code=exit_code,
        stdout_log_path=str(log_path) if log_path else None,
    )
