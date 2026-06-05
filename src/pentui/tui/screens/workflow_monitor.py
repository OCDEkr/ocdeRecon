"""Workflow monitor screen (PROJECT.md §7.4, §11).

Runs the WorkflowEngine in a worker, showing per-step status in a table and live
output in a log. Approval gates surface here as a modal (attended runs only).
"""

from __future__ import annotations

import contextlib

from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, RichLog, Static

from pentui.config import AppConfig
from pentui.core.registry import ToolRegistry
from pentui.core.workflow import (
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowEvent,
    WorkflowStep,
)
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import ScopeRuleRepository
from pentui.tui.screens.modals import GateApproveModal


class WorkflowMonitorScreen(Screen[None]):
    """Live per-step status and output for a running workflow."""

    DEFAULT_CSS = """
    WorkflowMonitorScreen { layout: vertical; }
    #title { padding: 0 1; text-style: bold; }
    #steps { height: auto; max-height: 40%; border: round $panel; margin: 0 1; }
    RichLog { height: 1fr; border: round $panel; margin: 0 1; }
    """

    BINDINGS = [
        ("r", "results", "Results"),
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(
        self,
        engagement: Engagement,
        registry: ToolRegistry,
        config: AppConfig,
        workflow: WorkflowDefinition,
        *,
        unattended: bool,
        is_root: bool,
    ) -> None:
        super().__init__()
        self.engagement = engagement
        self.registry = registry
        self.config = config
        self.workflow = workflow
        self.unattended = unattended
        self.is_root = is_root

    def compose(self) -> ComposeResult:
        mode = "unattended" if self.unattended else "attended"
        yield Header()
        yield Static(f"Workflow: {self.workflow.name}  ({mode})", id="title")
        yield DataTable(id="steps")
        yield RichLog(highlight=False, markup=False, wrap=True, id="log")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#steps", DataTable)
        table.add_column("Step", key="step")
        table.add_column("Tool", key="tool")
        table.add_column("Status", key="status")
        for step in self.workflow.steps:
            table.add_row(step.id, step.tool, "pending", key=step.id)
        self._run()

    def action_results(self) -> None:
        from pentui.tui.screens.results import ResultsScreen

        self.app.push_screen(ResultsScreen(self.engagement))

    def _on_event(self, event: WorkflowEvent) -> None:
        if event.kind == "status" and event.step_id:
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
        rules = ScopeRuleRepository(self.engagement.conn).list_for_project(
            self.engagement.project_id
        )
        engine = WorkflowEngine(
            self.engagement,
            self.registry,
            self.config,
            scope_rules=rules,
            unattended=self.unattended,
            is_root=self.is_root,
            event_sink=self._on_event,
            gate_approver=self._approve,
        )
        await engine.run(self.workflow)
        self.query_one("#log", RichLog).write("— workflow finished. Press r for results. —")
