"""Tool runners — the seam between the workflow engine and *how* a tool runs.

The engine owns all bookkeeping tool-agnostically: scan rows, scope filtering,
gates, event streaming, parsing, and artifact collection. A ``ToolRunner`` only
knows how to turn a prepared :class:`RunRequest` into output.

* :class:`ProcessRunner` runs an argv subprocess — every tool shipped today.
* A future ``RestRunner`` (PROJECT.md §14, Phase C) will drive an HTTP API
  (Nessus) with no subprocess at all, letting the engine admit non-CLI tools
  without special-casing them.

Runners stay UI-free and persistence-free: they take plain callbacks and return
plain data. ``executor.py`` (argv build + subprocess) is unchanged — this module
just composes it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from pentui.core.executor import ExecutorError, build_runs, preview, run_command
from pentui.core.manifest import ToolKind, ToolManifest, ToolProfile

#: A raw output line for display; the engine adds any prefix and routes it.
OnLine = Callable[[str], None]
#: A meta/marker line (command echo, sub-run header) — shown, not logged.
OnMarker = Callable[[str], None]


@dataclass(slots=True)
class RunRequest:
    """Everything a runner needs to execute one scan (one ``foreach`` group)."""

    manifest: ToolManifest
    profile: ToolProfile | None
    options: dict[str, str | bool]
    extra_args: list[str]
    targets: list[str]
    scan_dir: Path
    sudo: bool
    sudo_password: str | None = None


@dataclass(slots=True)
class RunPlan:
    """What a run *will* do — known before execution so the UI can show it."""

    command_str: str
    args: list[str]
    artifact_path: str | None
    #: Runner-private execution payload (ProcessRunner: the ``(label, argv)`` runs).
    runs: list[tuple[str, list[str]]] = field(default_factory=list)


@dataclass(slots=True)
class RunResult:
    ok: bool
    exit_code: int | None
    raw_output_path: str | None


class ToolRunner(Protocol):
    def prepare(self, req: RunRequest) -> RunPlan:
        """Build the run plan. May raise :class:`ExecutorError` on bad input."""
        ...

    async def execute(
        self, req: RunRequest, plan: RunPlan, *, on_line: OnLine, on_marker: OnMarker
    ) -> RunResult: ...


class ProcessRunner:
    """Runs a tool as an argv subprocess — the default for every manifest."""

    def prepare(self, req: RunRequest) -> RunPlan:
        runs = build_runs(
            req.manifest,
            profile=req.profile,
            options=req.options,
            extra_args=req.extra_args,
            targets=req.targets,
            scan_dir=str(req.scan_dir),
            sudo=req.sudo,
        )
        note = f"  (+{len(runs) - 1} more files)" if len(runs) > 1 else ""
        artifact = req.manifest.output.artifact
        artifact_path = (
            artifact.path.format(scan_dir=str(req.scan_dir)) if artifact is not None else None
        )
        return RunPlan(
            command_str=preview(runs[0][1]) + note,
            args=runs[0][1],
            artifact_path=artifact_path,
            runs=runs,
        )

    async def execute(
        self, req: RunRequest, plan: RunPlan, *, on_line: OnLine, on_marker: OnMarker
    ) -> RunResult:
        log_path = req.scan_dir / "stdout.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        exit_codes: list[int] = []
        with log_path.open("w", encoding="utf-8") as log:

            def tee(line: str) -> None:
                on_line(line)
                log.write(line + "\n")

            for sublabel, argv in plan.runs:
                if sublabel:
                    on_marker(f"=== {sublabel} ===")
                on_marker(f"$ {preview(argv)}")
                try:
                    result = await run_command(
                        argv,
                        on_line=tee,
                        stdin_data=req.sudo_password if req.sudo else None,
                    )
                except ExecutorError as exc:
                    on_marker(f"✗ {exc}")
                    exit_codes.append(127)
                    continue
                exit_codes.append(result.exit_code)

        ok = bool(exit_codes) and all(code == 0 for code in exit_codes)
        return RunResult(
            ok=ok,
            exit_code=exit_codes[-1] if exit_codes else None,
            raw_output_path=str(log_path),
        )


def get_runner(manifest: ToolManifest) -> ToolRunner:
    """The runner for a manifest, chosen by its ``kind``."""
    if manifest.kind is ToolKind.REST:
        raise NotImplementedError(
            f"{manifest.name!r}: REST tool execution is not available yet (Phase C)"
        )
    return ProcessRunner()
