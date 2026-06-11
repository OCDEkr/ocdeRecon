"""Workflow monitor screen (PROJECT.md §7.4, §11).

Runs the WorkflowEngine in a worker, showing per-step status in a table and live
output in a log. Approval gates surface here as a modal (attended runs only).
"""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import TYPE_CHECKING, cast

from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Header, RichLog, Static

from pentui.config import AppConfig
from pentui.core.registry import ToolRegistry
from pentui.core.workflow import (
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowEvent,
    WorkflowStep,
    workflow_needs_root,
)
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import ScopeRuleRepository
from pentui.tui.screens.modals import GateApproveModal

if TYPE_CHECKING:
    from pentui.app import PentuiApp


class WorkflowMonitorScreen(Screen[None]):
    """Live per-step status and output for a running workflow."""

    DEFAULT_CSS = """
    WorkflowMonitorScreen { layout: vertical; }
    #title { padding: 0 1; text-style: bold; }
    #steps { height: auto; max-height: 40%; border: round $panel; margin: 0 1; }
    RichLog { height: 1fr; border: round $panel; margin: 0 1; }
    """

    #: Braille spinner frames animated on the running step as a liveness heartbeat.
    _SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    BINDINGS = [
        ("s", "stop", "Stop"),
        ("r", "results", "Results"),
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def action_stop(self) -> None:
        self.workers.cancel_all()
        self.query_one("#log", RichLog).write("— stopping workflow… —")
        self.notify("Stopping workflow (current step is being terminated).")

    def __init__(
        self,
        engagement: Engagement,
        registry: ToolRegistry,
        config: AppConfig,
        workflows: list[WorkflowDefinition],
        *,
        unattended: bool,
        is_root: bool,
    ) -> None:
        super().__init__()
        self.engagement = engagement
        self.registry = registry
        self.config = config
        self.workflows = workflows
        self.unattended = unattended
        self.is_root = is_root
        self._spin: Timer | None = None
        self._spin_frame = 0
        #: The step currently animated as "running" (None when nothing is running).
        self._running_step: str | None = None
        self._running_since: datetime | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="title")
        yield DataTable(id="steps")
        yield RichLog(highlight=False, markup=False, wrap=True, id="log")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#steps", DataTable)
        table.add_column("Step", key="step")
        table.add_column("Tool", key="tool")
        table.add_column("Status", key="status")
        # A long, quiet step (e.g. nmap before it prints anything) must still read
        # as alive — animate the running step's status cell on a timer.
        self._spin = self.set_interval(0.5, self._tick)
        self._run()

    def _show_workflow(self, index: int, workflow: WorkflowDefinition) -> None:
        """Point the title + steps table at the workflow now running."""
        mode = "unattended" if self.unattended else "attended"
        position = f" [{index + 1}/{len(self.workflows)}]" if len(self.workflows) > 1 else ""
        self.query_one("#title", Static).update(f"Workflow{position}: {workflow.name}  ({mode})")
        self._running_step = None  # the previous workflow's running step is gone
        table = self.query_one("#steps", DataTable)
        table.clear()
        for step in workflow.steps:
            table.add_row(step.id, step.tool, "pending", key=step.id)

    def _tick(self) -> None:
        """Animate the running step's status so a quiet step doesn't look hung."""
        if self._running_step is None:
            return
        frame = self._SPINNER[self._spin_frame % len(self._SPINNER)]
        self._spin_frame += 1
        elapsed = ""
        if self._running_since is not None:
            secs = int((datetime.now() - self._running_since).total_seconds())
            elapsed = f"  ({secs // 60}:{secs % 60:02d})"
        with contextlib.suppress(Exception):
            table = self.query_one("#steps", DataTable)
            table.update_cell(self._running_step, "status", f"running {frame}{elapsed}")

    def action_results(self) -> None:
        from pentui.tui.screens.results import ResultsScreen

        self.app.push_screen(ResultsScreen(self.engagement))

    def _on_event(self, event: WorkflowEvent) -> None:
        if event.kind == "status" and event.step_id:
            if event.detail == "running":
                # Hand this step to the heartbeat; _tick animates it from here.
                self._running_step = event.step_id
                self._running_since = datetime.now()
            elif event.step_id == self._running_step:
                # done / error / skipped — stop animating; show the final state.
                self._running_step = None
            table = self.query_one("#steps", DataTable)
            with contextlib.suppress(KeyError):
                table.update_cell(event.step_id, "status", event.detail)
        else:
            prefix = f"[{event.step_id}] " if event.step_id else ""
            self.query_one("#log", RichLog).write(prefix + event.detail)

    async def _approve(self, step: WorkflowStep) -> bool:
        detail = f"{step.tool} ({step.profile or 'manual'}) is gated. Approve to run it."
        approved = await self.app.push_screen_wait(GateApproveModal(step.id, detail))
        return bool(approved)

    @work(exclusive=True)
    async def _run(self) -> None:
        log = self.query_one("#log", RichLog)
        # One sudo prompt covers the whole batch: ask if *any* workflow needs root.
        sudo_password = None
        if not self.is_root and any(
            workflow_needs_root(wf, self.registry) for wf in self.workflows
        ):
            sudo_password = await cast("PentuiApp", self.app).request_sudo_password()
            if sudo_password is None:
                log.write("— root password required; workflow(s) cancelled. —")
                return

        rules = ScopeRuleRepository(self.engagement.conn).list_for_project(
            self.engagement.project_id
        )
        # Sequential: one engine at a time on the shared engagement connection.
        failures = 0
        for index, workflow in enumerate(self.workflows):
            self._show_workflow(index, workflow)
            engine = WorkflowEngine(
                self.engagement,
                self.registry,
                self.config,
                scope_rules=rules,
                unattended=self.unattended,
                is_root=self.is_root,
                sudo_password=sudo_password,
                event_sink=self._on_event,
                gate_approver=self._approve,
            )
            await engine.run(workflow)
            failures += self._announce_done(workflow, engine)
        self._announce_batch_done(failures)

    def _announce_done(self, workflow: WorkflowDefinition, engine: WorkflowEngine) -> int:
        """Log one workflow's per-step summary; return its failed-step count."""
        from pentui.core.workflow import StepState

        failed = sum(1 for s in engine.states.values() if s is StepState.ERROR)
        skipped = sum(1 for s in engine.states.values() if s is StepState.SKIPPED)
        done = sum(1 for s in engine.states.values() if s is StepState.DONE)
        parts = [f"{done} done"]
        if failed:
            parts.append(f"{failed} failed")
        if skipped:
            parts.append(f"{skipped} skipped")
        self.query_one("#log", RichLog).write(f"— {workflow.name} finished ({', '.join(parts)}). —")
        return failed

    def _announce_batch_done(self, failures: int) -> None:
        """Signal a hands-off operator that every workflow finished (bell + notify)."""
        n = len(self.workflows)
        what = self.workflows[0].name if n == 1 else f"{n} workflows"
        summary = (
            f"{what}: {failures} failed step{'s' if failures != 1 else ''}"
            if failures
            else (f"{what} finished")
        )
        self.query_one("#log", RichLog).write(
            f"— {'all ' if n > 1 else ''}done ({summary}). Press r for results. —"
        )
        self.app.bell()
        self.notify(
            f"{summary} — press r for results.",
            title="Workflow finished",
            severity="warning" if failures else "information",
            timeout=10,
        )
