"""Command building + async subprocess execution (PROJECT.md §9).

Commands are built as argv LISTS — never a shell string, never ``shell=True``.
Free-text ``value`` inputs pass through named validators (incl. a baseline
shell-metacharacter check) before reaching argv. Root elevation is decided by the
caller (the TUI/workflow engine, which handle the sudo prompt); this module stays
UI-free and only prepends ``sudo`` when told to.
"""

from __future__ import annotations

import asyncio
import os
import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pentui.core.manifest import OptionType, TargetMode, ToolManifest, ToolProfile
from pentui.core.validators import ValidationFailed, validate_value

#: A user's option selections, keyed by option flag.
#: bool options -> True/False; value/choice options -> the string value.
OptionValues = Mapping[str, str | bool]


class ExecutorError(Exception):
    """Raised when a command cannot be built or launched."""


@dataclass(slots=True)
class CompletedScan:
    argv: list[str]
    exit_code: int
    stdout_log_path: str | None


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
    targets: Sequence[str] | None = None,
    scan_dir: str | Path | None = None,
    sudo: bool = False,
) -> list[str]:
    """Assemble the argv for a tool run. ``sudo`` is prepended only if requested."""
    argv: list[str] = ["sudo"] if sudo else []
    argv.append(manifest.binary)

    if profile is not None:
        argv.extend(profile.args)

    argv.extend(_option_tokens(manifest, options or {}))

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


def preview(argv: Sequence[str]) -> str:
    """Human-readable command line for display (not for execution)."""
    return shlex.join(argv)


async def run_command(
    argv: Sequence[str],
    *,
    scan_dir: str | Path | None = None,
    on_line: Callable[[str], None] | None = None,
    env: Mapping[str, str] | None = None,
) -> CompletedScan:
    """Run ``argv``, streaming merged stdout+stderr line-by-line.

    Each line is passed to ``on_line`` (if given) and teed to
    ``<scan_dir>/stdout.log`` (if ``scan_dir`` given). Returns on process exit.
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
            )
        except FileNotFoundError as exc:
            raise ExecutorError(f"command not found: {argv[0]!r}") from exc

        assert proc.stdout is not None
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
    finally:
        if log_handle is not None:
            log_handle.close()

    return CompletedScan(
        argv=argv,
        exit_code=exit_code,
        stdout_log_path=str(log_path) if log_path else None,
    )
