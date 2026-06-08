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

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

from pentui.config import AppConfig
from pentui.core.executor import (
    ExecutorError,
    build_argv,
    preview,
    requires_root,
    run_command,
)
from pentui.core.manifest import ToolManifest
from pentui.core.models import (
    GateState,
    Scan,
    ScanStatus,
    ScopeRule,
    StepRun,
    WorkflowRun,
    WorkflowStatus,
)
from pentui.core.query import QuerySpec, run_query
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
    gate: bool = False
    on_failure: str = "stop-branch"  # "stop-branch" | "continue"


class WorkflowDefaults(BaseModel):
    gates: bool = True


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
        topological_order(self.steps)  # raises on cycle
        return self


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


def save_workflow(wf: WorkflowDefinition, path: str | Path) -> Path:
    """Serialize a workflow to YAML that ``load_workflow`` round-trips.

    Emits only non-default fields so the file stays readable.
    """
    data: dict[str, object] = {"name": wf.name}
    if wf.description:
        data["description"] = wf.description
    if not wf.defaults.gates:
        data["defaults"] = {"gates": False}

    steps: list[dict[str, object]] = []
    for step in wf.steps:
        entry: dict[str, object] = {"id": step.id, "tool": step.tool}
        if step.profile:
            entry["profile"] = step.profile
        if step.options:
            entry["options"] = dict(step.options)
        if step.extra_args:
            entry["extra_args"] = list(step.extra_args)
        if step.after:
            entry["after"] = list(step.after)
        if step.targets is not None:
            entry["targets"] = {"from": step.targets.from_}
        if step.input is not None:
            query: dict[str, object] = {"from": step.input.from_, "as": step.input.as_.value}
            where: dict[str, object] = {}
            w = step.input.where
            if w.host_state:
                where["host_state"] = w.host_state
            if w.port_open_in:
                where["port_open_in"] = list(w.port_open_in)
            if w.service_name_in:
                where["service_name_in"] = list(w.service_name_in)
            if w.has_finding_severity is not None:
                where["has_finding_severity"] = w.has_finding_severity.value
            if w.hostname_matches:
                where["hostname_matches"] = w.hostname_matches
            if where:
                query["where"] = where
            entry["input"] = query
        if step.gate:
            entry["gate"] = True
        if step.on_failure != "stop-branch":
            entry["on_failure"] = step.on_failure
        steps.append(entry)
    data["steps"] = steps

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


#: Packaged workflows ship at <repo>/workflows alongside the src/ tree.
PACKAGED_WORKFLOWS_DIR = Path(__file__).resolve().parents[3] / "workflows"


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
        self.event_sink = event_sink
        self.gate_approver = gate_approver
        self.states: dict[str, StepState] = {}
        self.step_runs: dict[str, StepRun] = {}
        self._steps_by_id: dict[str, WorkflowStep] = {}
        self._gates_honored = True
        self._wf_name = ""

    async def run(self, wf: WorkflowDefinition) -> WorkflowRun:
        self._steps_by_id = {s.id: s for s in wf.steps}
        self._gates_honored = wf.defaults.gates
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

        targets = self._scope_filter(step, self._resolve_targets(step))
        if (step.input is not None or step.targets is not None) and not targets:
            self._skip(step, "no in-scope targets")
            return

        if not await self._gate_ok(step):
            return

        await self._execute(step, manifest, targets)

    def _resolve_targets(self, step: WorkflowStep) -> list[str]:
        if step.input is not None:
            return run_query(self.conn, self.project_id, step.input)
        if step.targets is not None and step.targets.from_ == "project":
            return [t.value for t in TargetRepository(self.conn).list_for_project(self.project_id)]
        return []

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
        self, step: WorkflowStep, manifest: ToolManifest, targets: list[str]
    ) -> None:
        profile = manifest.profile(step.profile) if step.profile else None
        need_root = requires_root(manifest, profile=profile, options=step.options)
        use_sudo = need_root and not self.is_root

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
        scan_dir = str(self.config.scan_dir(self.engagement.name, scan.id))
        try:
            argv = build_argv(
                manifest, profile=profile, options=step.options,
                extra_args=step.extra_args, targets=targets, scan_dir=scan_dir, sudo=use_sudo,
            )
        except ExecutorError as exc:
            scan.status = ScanStatus.ERROR
            scans.update(scan)
            self._fail(step, str(exc), scan_id=scan.id)
            return

        scan.command_str = preview(argv)
        scan.args = argv
        if manifest.output.artifact is not None:
            scan.artifact_path = manifest.output.artifact.path.format(scan_dir=scan_dir)
        scans.update(scan)
        if use_sudo:
            self._audit("sudo_run", scan.command_str)

        self._emit(step.id, "line", f"$ {scan.command_str}")
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now()
        scans.update(scan)
        try:
            result = await run_command(
                argv, scan_dir=scan_dir,
                on_line=lambda line: self._emit(step.id, "line", line),
            )
        except ExecutorError as exc:
            scan.status = ScanStatus.ERROR
            scan.finished_at = datetime.now()
            scans.update(scan)
            self._fail(step, str(exc), scan_id=scan.id)
            return

        scan.exit_code = result.exit_code
        scan.raw_output_path = result.stdout_log_path
        scan.finished_at = datetime.now()
        scan.status = ScanStatus.DONE if result.exit_code == 0 else ScanStatus.ERROR
        scans.update(scan)

        if result.exit_code == 0:
            self._persist(scan, manifest)
            self._done(step, scan_id=scan.id)
        else:
            self._fail(step, f"exit code {result.exit_code}", scan_id=scan.id)

    def _persist(self, scan: Scan, manifest: ToolManifest) -> None:
        parser_name = manifest.output.parser
        if not parser_name:
            return
        parser = get_parser(parser_name)
        if parser is None:
            return
        ctx = ParseContext(
            raw_stdout="", raw_stderr="", artifact_path=scan.artifact_path,
            scan_id=scan.id or 0, project_id=self.project_id,
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

    def _done(self, step: WorkflowStep, *, scan_id: int) -> None:
        self._transition(step, StepState.DONE, finished=True, scan_id=scan_id)

    def _fail(self, step: WorkflowStep, reason: str, *, scan_id: int | None = None) -> None:
        self._emit(step.id, "line", f"✗ {reason}")
        self._transition(step, StepState.ERROR, finished=True, scan_id=scan_id)
        if step.on_failure == "stop-branch":
            self._skip_descendants(step.id, "upstream step failed")

    def _skip(
        self, step: WorkflowStep, reason: str, *, skip_descendants: bool = False
    ) -> None:
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
