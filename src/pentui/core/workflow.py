"""Workflow definitions + the orchestration engine (PROJECT.md §7) — the core purpose.

A workflow is a branching DAG of steps; each step names a tool (+ profile/options),
declares which steps it runs ``after``, and optionally queries upstream results
(via ``pentui.core.query``) for its inputs. The engine runs steps in dependency
order, applies gates (auto-approved when the run is unattended), skips-and-logs
out-of-scope targets, parses+persists each step's output so downstream queries see
it, and records WorkflowRun/StepRun state.

Steps run sequentially in a valid topological order (dependencies respected;
fan-out is expressed in the DAG). Concurrent execution of independent branches is
a future optimization — see PROJECT.md §16.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

from pentui.config import AppConfig
from pentui.core.executor import (
    ExecutorError,
    build_runs,
    preview,
    requires_root,
    run_command,
)
from pentui.core.manifest import ToolManifest, ToolProfile
from pentui.core.models import (
    GateState,
    Scan,
    ScanStatus,
    ScopeRule,
    StepRun,
    WorkflowRun,
    WorkflowStatus,
)
from pentui.core.query import QuerySpec, group_by_subnet, materialize, run_query, select_hosts
from pentui.core.registry import ToolRegistry
from pentui.core.scope import classify_targets
from pentui.parsers import get_parser
from pentui.parsers.base import ParseContext
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import (
    AuditLogRepository,
    ScanRepository,
    StepRunRepository,
    TargetRepository,
    WorkflowRunRepository,
)
from pentui.persistence.store import merge_scan_result


class WorkflowError(Exception):
    """Raised when a workflow definition is malformed (bad refs, cycles, …)."""


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
class StepTargets(BaseModel):
    from_: str = Field(alias="from")  # currently only "project"
    model_config = {"populate_by_name": True}


class FileFrom(BaseModel):
    """Bind a file-input flag to an upstream step's collected-artifact directory."""

    step: str
    flag: str


class WorkflowStep(BaseModel):
    id: str
    tool: str
    profile: str | None = None
    options: dict[str, str | bool] = Field(default_factory=dict)
    #: Extra raw argv tokens appended after profile/options (operator-authored).
    extra_args: list[str] = Field(default_factory=list)
    after: list[str] = Field(default_factory=list)
    targets: StepTargets | None = None
    input: QuerySpec | None = None
    #: Fan out into one run per group, e.g. "subnet/24" runs once per /24 of the
    #: hosts selected by ``input``.
    foreach: str | None = None
    #: What each ``foreach`` run targets. "hosts" (default) scans only the IPs
    #: selected by ``input`` in that group; "subnet" scans the whole group CIDR
    #: (e.g. 192.168.5.0/24) — catching hosts a fast upstream sweep (masscan)
    #: missed — falling back to the in-scope hosts when the CIDR isn't wholly in
    #: scope, so a hit subnet is never skipped nor scanned out of scope.
    foreach_target: Literal["hosts", "subnet"] = "hosts"
    #: Feed a file-input flag (e.g. gowitness -f) the collected artifacts of an
    #: upstream step's runs (e.g. the per-/24 nmap XMLs), batching over them.
    file_from: FileFrom | None = None
    gate: bool = False
    on_failure: str = "stop-branch"  # "stop-branch" | "continue"


class WorkflowDefaults(BaseModel):
    gates: bool = True
    #: Max ``foreach`` runs in flight at once (e.g. per-/24 nmap scans). Falls
    #: back to ``config.max_concurrent_scans`` when unset.
    max_parallel: int | None = None


class WorkflowDefinition(BaseModel):
    name: str
    description: str | None = None
    defaults: WorkflowDefaults = Field(default_factory=WorkflowDefaults)
    steps: list[WorkflowStep]

    @model_validator(mode="after")
    def _validate_dag(self) -> WorkflowDefinition:
        ids = [s.id for s in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate step ids")
        idset = set(ids)
        for step in self.steps:
            for dep in step.after:
                if dep not in idset:
                    raise ValueError(f"step {step.id!r} depends on unknown step {dep!r}")
            if step.foreach is not None:
                subnet_prefix(step.foreach)  # validates "subnet/<n>"
                if step.input is None:
                    raise ValueError(f"step {step.id!r} has 'foreach' but no 'input' query")
            if step.file_from is not None and step.file_from.step not in idset:
                raise ValueError(
                    f"step {step.id!r} file_from references unknown step {step.file_from.step!r}"
                )
        topological_order(self.steps)  # raises on cycle
        return self


def subnet_prefix(foreach: str) -> int:
    """Parse a ``foreach`` grouping like 'subnet/24' -> 24. Raises on bad format."""
    match = re.fullmatch(r"subnet/(\d{1,3})", foreach.strip())
    if not match or not 0 < int(match.group(1)) <= 128:
        raise ValueError(f"invalid foreach {foreach!r} (expected 'subnet/<1-128>')")
    return int(match.group(1))


def topological_order(steps: list[WorkflowStep]) -> list[str]:
    """Kahn's algorithm. Returns step ids in a valid run order; raises on a cycle."""
    deps = {s.id: set(s.after) for s in steps}
    order: list[str] = []
    ready = [sid for sid, d in deps.items() if not d]
    while ready:
        sid = ready.pop(0)
        order.append(sid)
        for other, d in deps.items():
            if sid in d:
                d.discard(sid)
                if not d and other not in order and other not in ready:
                    ready.append(other)
    if len(order) != len(steps):
        raise WorkflowError("workflow has a dependency cycle")
    return order


def load_workflow(path: str | Path) -> WorkflowDefinition:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        raise WorkflowError(f"{path}: could not read/parse YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise WorkflowError(f"{path}: top level must be a mapping")
    try:
        return WorkflowDefinition.model_validate(raw)
    except ValidationError as exc:
        raise WorkflowError(f"{path}: invalid workflow:\n{exc}") from exc


#: Packaged workflows ship inside the package (src/pentui/workflows).
PACKAGED_WORKFLOWS_DIR = Path(__file__).resolve().parents[1] / "workflows"


class WorkflowRegistry:
    def __init__(self) -> None:
        self._workflows: dict[str, WorkflowDefinition] = {}
        self.errors: list[str] = []

    def load_dir(self, directory: str | Path) -> None:
        directory = Path(directory)
        if not directory.is_dir():
            return
        for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
            try:
                wf = load_workflow(path)
            except WorkflowError as exc:
                self.errors.append(str(exc))
                continue
            self._workflows[wf.name] = wf

    def get(self, name: str) -> WorkflowDefinition | None:
        return self._workflows.get(name)

    def names(self) -> list[str]:
        return sorted(self._workflows)

    def all(self) -> list[WorkflowDefinition]:
        return [self._workflows[name] for name in self.names()]


def build_workflow_registry(*directories: str | Path) -> WorkflowRegistry:
    registry = WorkflowRegistry()
    registry.load_dir(PACKAGED_WORKFLOWS_DIR)
    for directory in directories:
        registry.load_dir(directory)
    return registry


def workflow_needs_root(wf: WorkflowDefinition, registry: ToolRegistry) -> bool:
    """Whether any step's command would require root (so we must capture sudo)."""
    for step in wf.steps:
        manifest = registry.get(step.tool)
        if manifest is None:
            continue
        profile = manifest.profile(step.profile) if step.profile else None
        if requires_root(manifest, profile=profile, options=step.options):
            return True
    return False


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class StepState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(slots=True)
class WorkflowEvent:
    step_id: str
    kind: str  # "status" | "line"
    detail: str


GateApprover = Callable[[WorkflowStep], Awaitable[bool]]
EventSink = Callable[[WorkflowEvent], None]


class WorkflowEngine:
    """Runs a WorkflowDefinition against an engagement."""

    def __init__(
        self,
        engagement: Engagement,
        registry: ToolRegistry,
        config: AppConfig,
        *,
        scope_rules: list[ScopeRule] | None = None,
        unattended: bool = False,
        is_root: bool = False,
        sudo_password: str | None = None,
        event_sink: EventSink | None = None,
        gate_approver: GateApprover | None = None,
    ) -> None:
        self.engagement = engagement
        self.conn = engagement.conn
        self.project_id = engagement.project_id
        self.registry = registry
        self.config = config
        self.scope_rules = scope_rules or []
        self.unattended = unattended
        self.is_root = is_root
        self.sudo_password = sudo_password
        self.event_sink = event_sink
        self.gate_approver = gate_approver
        self.states: dict[str, StepState] = {}
        self.step_runs: dict[str, StepRun] = {}
        self._steps_by_id: dict[str, WorkflowStep] = {}
        self._gates_honored = True
        self._max_parallel = config.max_concurrent_scans
        self._wf_name = ""

    async def run(self, wf: WorkflowDefinition) -> WorkflowRun:
        self._steps_by_id = {s.id: s for s in wf.steps}
        self._gates_honored = wf.defaults.gates
        self._max_parallel = wf.defaults.max_parallel or self.config.max_concurrent_scans
        self._wf_name = wf.name
        self.states = {s.id: StepState.PENDING for s in wf.steps}

        run_row = WorkflowRunRepository(self.conn).create(
            WorkflowRun(
                project_id=self.project_id,
                workflow_name=wf.name,
                definition_json=wf.model_dump_json(by_alias=True),
                status=WorkflowStatus.RUNNING,
                unattended=self.unattended,
                started_at=datetime.now(),
            )
        )
        for sid in topological_order(wf.steps):
            if self.states[sid] is StepState.SKIPPED:
                continue
            await self._run_step(run_row, self._steps_by_id[sid])

        run_row.status = WorkflowStatus.DONE
        run_row.finished_at = datetime.now()
        WorkflowRunRepository(self.conn).update(run_row)
        return run_row

    # -- per-step ---------------------------------------------------------- #
    async def _run_step(self, run_row: WorkflowRun, step: WorkflowStep) -> None:
        step_run = StepRunRepository(self.conn).create(
            StepRun(workflow_run_id=run_row.id or 0, step_id=step.id, tool=step.tool)
        )
        self.step_runs[step.id] = step_run
        self._transition(step, StepState.RUNNING, started=True)

        manifest = self.registry.get(step.tool)
        if manifest is None:
            self._fail(step, f"unknown tool {step.tool!r}")
            return

        if not await self._gate_ok(step):
            return

        await self._execute(run_row, step, manifest)

    def _resolve_targets(self, step: WorkflowStep) -> list[str]:
        if step.input is not None:
            return run_query(self.conn, self.project_id, step.input)
        if step.targets is not None and step.targets.from_ == "project":
            return [t.value for t in TargetRepository(self.conn).list_for_project(self.project_id)]
        return []

    def _in_scope(self, target: str) -> bool:
        """True if ``target`` is allowed by scope. Quiet (no skip log/audit) —
        used to decide a target *before* committing, unlike ``_scope_filter``."""
        return all(not d.blocked for d in classify_targets(self.scope_rules, [target]))

    def _scope_filter(self, step: WorkflowStep, targets: list[str]) -> list[str]:
        kept: list[str] = []
        for decision in classify_targets(self.scope_rules, targets):
            if decision.blocked:
                self._audit("scope_skip", f"{self._wf_name}.{step.id}: {decision.target}")
                self._emit(step.id, "line", f"⛔ skipped out-of-scope target {decision.target}")
            else:
                kept.append(decision.target)
        return kept

    async def _gate_ok(self, step: WorkflowStep) -> bool:
        if not (step.gate and self._gates_honored):
            return True
        if self.unattended:
            self._audit("gate_auto_approved", f"{self._wf_name}.{step.id}")
            self._emit(step.id, "line", "gate auto-approved (unattended)")
            return True
        approved = await self.gate_approver(step) if self.gate_approver else True
        if not approved:
            self.step_runs[step.id].gate_state = GateState.SKIPPED
            self._skip(step, "gate declined", skip_descendants=True)
            return False
        self.step_runs[step.id].gate_state = GateState.APPROVED
        return True

    async def _execute(
        self, run_row: WorkflowRun, step: WorkflowStep, manifest: ToolManifest
    ) -> None:
        run_id = run_row.id or 0
        options = dict(step.options)
        if step.file_from is not None:
            src = self.config.workflow_artifacts_dir(
                self.engagement.name, run_id, step.file_from.step
            )
            if not src.is_dir() or not any(src.iterdir()):
                self._skip(step, f"no artifacts collected from {step.file_from.step!r}")
                return
            options[step.file_from.flag] = str(src)

        groups = self._run_groups(step)
        if not groups:
            self._skip(step, "no in-scope targets")
            return

        profile = manifest.profile(step.profile) if step.profile else None
        use_sudo = requires_root(manifest, profile=profile, options=options) and not self.is_root
        artifacts_out = self.config.workflow_artifacts_dir(self.engagement.name, run_id, step.id)

        # Fan-out groups (e.g. per-/24 nmap scans) run concurrently, bounded so we
        # don't launch hundreds of scans — or trip an IDS — at once. A single
        # group degenerates to one task. Their DB writes happen in synchronous
        # bursts between awaits, so the shared connection is never mid-transaction
        # across coroutines; cancelling the worker (Stop) propagates through
        # gather into each run_command, which terminates its process group.
        sem = asyncio.Semaphore(max(1, self._max_parallel))

        async def _bounded(label: str, targets: list[str]) -> tuple[bool, int | None]:
            async with sem:
                return await self._run_group(
                    step, manifest, profile, options, use_sudo, label, targets, artifacts_out
                )

        results = await asyncio.gather(*(_bounded(label, t) for label, t in groups))
        all_ok = all(ok for ok, _ in results)
        last_scan_id = next((sid for _, sid in reversed(results) if sid), None)

        if all_ok:
            self._done(step, scan_id=last_scan_id)
        else:
            self._fail(step, "a run failed", scan_id=last_scan_id)

    def _run_groups(self, step: WorkflowStep) -> list[tuple[str, list[str]]]:
        """Resolve the run groups: one per /24 for foreach, else a single group."""
        if step.foreach is not None and step.input is not None:
            prefix = subnet_prefix(step.foreach)
            hosts = select_hosts(self.conn, self.project_id, step.input)
            groups: list[tuple[str, list[str]]] = []
            for net, group_hosts in group_by_subnet(hosts, prefix):
                # "subnet" mode scans the whole group CIDR, but only if it's
                # wholly in scope; otherwise narrow to the discovered in-scope
                # hosts so a hit subnet is neither skipped nor scanned out of
                # scope. "hosts" mode always scans just the selected IPs.
                if step.foreach_target == "subnet" and self._in_scope(net):
                    candidate = [net]
                else:
                    candidate = materialize(group_hosts, step.input)
                targets = self._scope_filter(step, candidate)
                if targets:
                    groups.append((net.replace("/", "_"), targets))
            return groups
        if step.input is not None or step.targets is not None:
            targets = self._scope_filter(step, self._resolve_targets(step))
            return [("", targets)] if targets else []
        return [("", [])]  # no targets (e.g. a file_from step, or a listener)

    async def _run_group(
        self,
        step: WorkflowStep,
        manifest: ToolManifest,
        profile: ToolProfile | None,
        options: dict[str, str | bool],
        use_sudo: bool,
        label: str,
        targets: list[str],
        artifacts_out: Path,
    ) -> tuple[bool, int | None]:
        scans = ScanRepository(self.conn)
        scan = scans.create(
            Scan(
                project_id=self.project_id,
                tool=step.tool,
                profile=step.profile,
                ran_as_root=use_sudo,
                step_run_id=self.step_runs[step.id].id,
            )
        )
        assert scan.id is not None
        scan_dir = self.config.scan_dir(self.engagement.name, scan.id, tool=step.tool)
        try:
            runs = build_runs(
                manifest,
                profile=profile,
                options=options,
                extra_args=step.extra_args,
                targets=targets,
                scan_dir=str(scan_dir),
                sudo=use_sudo,
            )
        except ExecutorError as exc:
            scan.status = ScanStatus.ERROR
            scans.update(scan)
            self._emit(step.id, "line", f"✗ {exc}")
            return False, scan.id

        note = f"  (+{len(runs) - 1} more files)" if len(runs) > 1 else ""
        scan.command_str = preview(runs[0][1]) + note
        scan.args = runs[0][1]
        if manifest.output.artifact is not None:
            scan.artifact_path = manifest.output.artifact.path.format(scan_dir=str(scan_dir))
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now()
        scans.update(scan)
        if use_sudo:
            self._audit("sudo_run", scan.command_str)

        prefix = f"[{label}] " if label else ""
        log_path = scan_dir / "stdout.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        exit_codes: list[int] = []
        with log_path.open("w", encoding="utf-8") as log:

            def on_line(line: str) -> None:
                self._emit(step.id, "line", prefix + line)
                log.write(line + "\n")

            for sublabel, argv in runs:
                if sublabel:
                    self._emit(step.id, "line", f"{prefix}=== {sublabel} ===")
                self._emit(step.id, "line", f"{prefix}$ {preview(argv)}")
                try:
                    result = await run_command(
                        argv,
                        on_line=on_line,
                        stdin_data=self.sudo_password if use_sudo else None,
                    )
                except ExecutorError as exc:
                    self._emit(step.id, "line", f"{prefix}✗ {exc}")
                    exit_codes.append(127)
                    continue
                exit_codes.append(result.exit_code)

        scan.exit_code = exit_codes[-1] if exit_codes else None
        scan.raw_output_path = str(log_path)
        scan.finished_at = datetime.now()
        ok = bool(exit_codes) and all(code == 0 for code in exit_codes)
        scan.status = ScanStatus.DONE if ok else ScanStatus.ERROR
        scans.update(scan)

        if ok:
            self._persist(scan, manifest)
            self._collect_artifact(scan, manifest, artifacts_out, label)
        return ok, scan.id

    def _collect_artifact(
        self, scan: Scan, manifest: ToolManifest, artifacts_out: Path, label: str
    ) -> None:
        """Copy this run's artifact into the step's shared dir for downstream file_from."""
        if manifest.output.artifact is None or not scan.artifact_path:
            return
        src = Path(scan.artifact_path)
        if not src.exists():
            return
        artifacts_out.mkdir(parents=True, exist_ok=True)
        name = (label or str(scan.id)) + src.suffix
        shutil.copyfile(src, artifacts_out / name)

    def _persist(self, scan: Scan, manifest: ToolManifest) -> None:
        parser_name = manifest.output.parser
        if not parser_name:
            return
        parser = get_parser(parser_name)
        if parser is None:
            return
        ctx = ParseContext(
            raw_stdout="",
            raw_stderr="",
            artifact_path=scan.artifact_path,
            scan_id=scan.id or 0,
            project_id=self.project_id,
        )
        summary = merge_scan_result(self.conn, self.project_id, scan.id, parser(ctx))
        self._emit(
            "",  # belongs to the step but reported generically
            "line",
            f"  parsed: {summary.hosts} hosts, {summary.open_ports} open ports, "
            f"{summary.findings} findings",
        )

    # -- state transitions ------------------------------------------------- #
    def _transition(
        self,
        step: WorkflowStep,
        state: StepState,
        *,
        started: bool = False,
        finished: bool = False,
        scan_id: int | None = None,
    ) -> None:
        self.states[step.id] = state
        step_run = self.step_runs[step.id]
        step_run.status = _SCAN_STATUS[state]
        if scan_id is not None:
            step_run.scan_id = scan_id
        if started:
            step_run.started_at = datetime.now()
        if finished:
            step_run.finished_at = datetime.now()
        StepRunRepository(self.conn).update(step_run)
        self._emit(step.id, "status", state.value)

    def _done(self, step: WorkflowStep, *, scan_id: int | None) -> None:
        self._transition(step, StepState.DONE, finished=True, scan_id=scan_id)

    def _fail(self, step: WorkflowStep, reason: str, *, scan_id: int | None = None) -> None:
        self._emit(step.id, "line", f"✗ {reason}")
        self._transition(step, StepState.ERROR, finished=True, scan_id=scan_id)
        if step.on_failure == "stop-branch":
            self._skip_descendants(step.id, "upstream step failed")

    def _skip(self, step: WorkflowStep, reason: str, *, skip_descendants: bool = False) -> None:
        self._emit(step.id, "line", f"↷ skipped: {reason}")
        self._transition(step, StepState.SKIPPED, finished=True)
        if skip_descendants:
            self._skip_descendants(step.id, "upstream step skipped")

    def _skip_descendants(self, step_id: str, reason: str) -> None:
        for desc in self._descendants(step_id):
            if self.states.get(desc) is StepState.PENDING:
                self.states[desc] = StepState.SKIPPED
                self._emit(desc, "status", f"skipped ({reason})")

    def _descendants(self, step_id: str) -> set[str]:
        result: set[str] = set()
        frontier = [step_id]
        while frontier:
            current = frontier.pop()
            for s in self._steps_by_id.values():
                if current in s.after and s.id not in result:
                    result.add(s.id)
                    frontier.append(s.id)
        return result

    # -- helpers ----------------------------------------------------------- #
    def _emit(self, step_id: str, kind: str, detail: str) -> None:
        if self.event_sink is not None:
            self.event_sink(WorkflowEvent(step_id, kind, detail))

    def _audit(self, action: str, detail: str) -> None:
        AuditLogRepository(self.conn).log(self.project_id, action, detail)


_SCAN_STATUS = {
    StepState.PENDING: ScanStatus.QUEUED,
    StepState.RUNNING: ScanStatus.RUNNING,
    StepState.DONE: ScanStatus.DONE,
    StepState.ERROR: ScanStatus.ERROR,
    StepState.SKIPPED: ScanStatus.CANCELLED,
}
