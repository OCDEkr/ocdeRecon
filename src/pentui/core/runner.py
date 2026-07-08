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

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from pentui.config import AppConfig, NessusSettings, target_slug
from pentui.core.executor import ExecutorError, build_runs, preview, run_command
from pentui.core.manifest import ToolKind, ToolManifest, ToolProfile
from pentui.core.nessus_client import OK_STATUSES, NessusClient, NessusError

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
    #: Where the run's stdout log is written; defaults to ``scan_dir/stdout.log``
    #: when unset. The engine sets it so flat-layout runs (which share the tool
    #: folder) get a per-target log under ``scans/<tool>/logs/``.
    log_path: Path | None = None
    #: The ``{name}`` artifact stem — the caller-resolved, disambiguated target
    #: label. Defaults to ``target_slug(targets)`` when unset.
    name: str | None = None
    #: Override the scan name (REST tools only); ignored by ProcessRunner.
    scan_name: str | None = None


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
        name = req.name or target_slug(req.targets) or "scan"
        runs = build_runs(
            req.manifest,
            profile=req.profile,
            options=req.options,
            extra_args=req.extra_args,
            targets=req.targets,
            scan_dir=str(req.scan_dir),
            name=name,
            sudo=req.sudo,
        )
        note = f"  (+{len(runs) - 1} more files)" if len(runs) > 1 else ""
        artifact = req.manifest.output.artifact
        artifact_path = (
            artifact.path.format(scan_dir=str(req.scan_dir), name=name)
            if artifact is not None
            else None
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
        log_path = req.log_path or req.scan_dir / "stdout.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # Tools that emit a directory of output (gowitness) write it relative to
        # the cwd, so run them *in* their scan folder; single-artifact tools use
        # an explicit output path and keep pentui's own cwd.
        cwd = req.scan_dir if req.manifest.output.dir_output else None
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
                        cwd=cwd,
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


#: Builds the real Nessus client (TLS verification off for the self-signed
#: localhost cert). Swapped out in tests via the RestRunner client factory.
def _make_nessus_client(settings: NessusSettings) -> NessusClient:
    import httpx

    assert settings.access_key is not None and settings.secret_key is not None
    http = httpx.AsyncClient(base_url=settings.url, verify=False, timeout=30.0)  # noqa: S501
    return NessusClient(settings.url, settings.access_key, settings.secret_key, http)


ClientFactory = Callable[[NessusSettings], NessusClient]


def _nessus_settings(options: dict[str, str | bool]) -> dict[str, str]:
    """Translate a REST step's ``options`` into Nessus scan-policy preferences.

    Nessus expects string values; booleans map to its ``"yes"``/``"no"`` form
    (e.g. ``test_local_nessus_host: false`` → ``"no"`` to skip the scanner's own
    host). Any value already a string passes through unchanged.
    """
    return {
        k: ("yes" if v else "no") if isinstance(v, bool) else str(v) for k, v in options.items()
    }


class RestRunner:
    """Runs a scan via an HTTP API instead of a subprocess (Nessus today).

    The engine treats it exactly like ProcessRunner — same scan rows, scope
    filtering (targets are pre-filtered before we ever get here), event stream,
    artifact, and parsing. The artifact is the exported ``.nessus`` file, parsed
    by the ``nessus`` parser into the unified model.
    """

    def __init__(self, config: AppConfig, *, client_factory: ClientFactory | None = None) -> None:
        self.config = config
        self._client_factory = client_factory or _make_nessus_client

    def prepare(self, req: RunRequest) -> RunPlan:
        stem = req.name or target_slug(req.targets) or "nessus"
        artifact_path = str(req.scan_dir / f"{stem}.nessus")
        n = len(req.targets)
        settings = self.config.nessus_settings()
        name = req.scan_name or f"pentui {stem}"
        return RunPlan(
            command_str=f"[nessus REST] scan {n} target(s) as {name!r} via {settings.url}",
            args=[],
            artifact_path=artifact_path,
        )

    async def execute(
        self, req: RunRequest, plan: RunPlan, *, on_line: OnLine, on_marker: OnMarker
    ) -> RunResult:
        settings = self.config.nessus_settings()
        log_path = req.log_path or req.scan_dir / "stdout.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        if not settings.configured:
            on_marker(
                "✗ Nessus API keys not set — add them to settings.json under 'nessus' "
                "or set NESSUS_ACCESS_KEY / NESSUS_SECRET_KEY."
            )
            log_path.write_text("Nessus API keys not configured.\n")
            return RunResult(ok=False, exit_code=None, raw_output_path=str(log_path))

        client = self._client_factory(settings)
        scan_id: int | None = None
        ok = False
        with log_path.open("w", encoding="utf-8") as log:

            def emit(line: str) -> None:
                on_line(line)
                log.write(line + "\n")

            on_marker(plan.command_str)
            try:
                name = req.scan_name or f"pentui {req.name or req.scan_dir.name}"
                scan_id = await client.launch(
                    req.targets, name=name, settings=_nessus_settings(req.options)
                )
                emit(f"launched Nessus scan {scan_id}")
                status = await client.wait(scan_id, on_status=lambda s: emit(f"status: {s}"))
                emit(f"scan finished: {status}")
                if status in OK_STATUSES:
                    await client.export_nessus(scan_id, plan.artifact_path or "")
                    emit(f"exported results to {plan.artifact_path}")
                    ok = True
                else:
                    emit(f"scan did not complete cleanly ({status}); nothing to parse")
            except asyncio.CancelledError:
                if scan_id is not None:
                    with contextlib.suppress(Exception):
                        await client.stop(scan_id)
                raise
            except NessusError as exc:
                on_marker(f"✗ {exc}")
                emit(f"error: {exc}")
            finally:
                with contextlib.suppress(Exception):
                    await client.aclose()

        return RunResult(ok=ok, exit_code=0 if ok else 1, raw_output_path=str(log_path))


def get_runner(manifest: ToolManifest, config: AppConfig | None = None) -> ToolRunner:
    """The runner for a manifest, chosen by its ``kind``.

    ``config`` is required for REST tools (they read connection settings from it);
    process tools ignore it.
    """
    if manifest.kind is ToolKind.REST:
        if config is None:
            raise ExecutorError(f"{manifest.name!r}: REST tools require app config")
        return RestRunner(config)
    return ProcessRunner()
