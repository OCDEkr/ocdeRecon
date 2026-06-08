"""Workflow launch screen (PROJECT.md §7, §11).

Pick a workflow, choose attended vs. unattended, and launch it — or press 'b' to
build a new one. If any step needs root we authenticate sudo once up front
(suspending the app) so the engine can elevate per-step without re-prompting.
"""

from __future__ import annotations

import os
import subprocess

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Label, ListItem, ListView, Static

from pentui.config import AppConfig
from pentui.core.executor import requires_root
from pentui.core.registry import ToolRegistry, tool_available
from pentui.core.workflow import WorkflowDefinition, WorkflowRegistry, build_workflow_registry
from pentui.persistence.engagement import Engagement


class WorkflowLaunchScreen(Screen[None]):
    """Choose and launch a workflow for the engagement, or build a new one."""

    DEFAULT_CSS = """
    WorkflowLaunchScreen { layout: vertical; }
    #workflows { height: 1fr; min-height: 5; border: round $panel; margin: 0 1; }
    #detail { height: auto; border: round $panel; margin: 0 1; padding: 0 1; }
    #controls { height: auto; padding: 0 1; }
    Button { margin: 1 1 0 0; }
    """

    BINDINGS = [
        ("b", "build", "Build new"),
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(
        self, engagement: Engagement, registry: ToolRegistry, config: AppConfig
    ) -> None:
        super().__init__()
        self.engagement = engagement
        self.registry = registry
        self.config = config
        self.workflows: WorkflowRegistry = build_workflow_registry(config.user_workflows_dir)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Workflows (Enter to select, b to build a new one):")
        yield ListView(id="workflows")
        yield Static("Select a workflow.", id="detail")
        with Horizontal(id="controls"):
            yield Checkbox("Unattended (skip approval gates)", id="unattended")
            yield Button("Launch", variant="primary", id="launch")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh()

    def on_screen_resume(self) -> None:
        # Pick up workflows created in the builder this session.
        self._refresh()

    def _refresh(self) -> None:
        self.workflows = build_workflow_registry(self.config.user_workflows_dir)
        for error in self.workflows.errors:
            self.notify(error, severity="error", title="Workflow error", timeout=10)
        view = self.query_one("#workflows", ListView)
        view.clear()
        for name in self.workflows.names():
            view.append(ListItem(Label(name), name=name))
        if not self.workflows.names():
            self.query_one("#detail", Static).update(
                "No workflows yet — press [b]b[/b] to build one."
            )

    def _selected(self) -> WorkflowDefinition | None:
        item = self.query_one("#workflows", ListView).highlighted_child
        if item is None or item.name is None:
            return None
        return self.workflows.get(item.name)

    @on(ListView.Highlighted, "#workflows")
    def _show_detail(self) -> None:
        wf = self._selected()
        if wf is None:
            return
        lines = [f"[b]{wf.name}[/b] — {wf.description or ''}", ""]
        for step in wf.steps:
            after = f"  after {', '.join(step.after)}" if step.after else ""
            gate = "  [gate]" if step.gate else ""
            manifest = self.registry.get(step.tool)
            if manifest is None:
                missing = "  [red](unknown tool)[/red]"
            elif not tool_available(manifest):
                missing = "  [yellow](binary not found)[/yellow]"
            else:
                missing = ""
            lines.append(
                f"• {step.id}: {step.tool} ({step.profile or 'manual'}){after}{gate}{missing}"
            )
        self.query_one("#detail", Static).update("\n".join(lines))

    def action_build(self) -> None:
        from pentui.tui.screens.workflow_builder import WorkflowBuilderScreen

        self.app.push_screen(
            WorkflowBuilderScreen(self.engagement, self.registry, self.config)
        )

    @on(Button.Pressed, "#launch")
    def _launch(self) -> None:
        wf = self._selected()
        if wf is None:
            self.notify("Select a workflow first.", severity="warning")
            return
        unattended = self.query_one("#unattended", Checkbox).value
        is_root = os.geteuid() == 0
        if self._needs_root(wf) and not is_root and not self._elevate():
            return
        from pentui.tui.screens.workflow_monitor import WorkflowMonitorScreen

        self.app.push_screen(
            WorkflowMonitorScreen(
                self.engagement, self.registry, self.config, wf,
                unattended=unattended, is_root=is_root,
            )
        )

    def _needs_root(self, wf: WorkflowDefinition) -> bool:
        for step in wf.steps:
            manifest = self.registry.get(step.tool)
            if manifest is None:
                continue
            profile = manifest.profile(step.profile) if step.profile else None
            if requires_root(manifest, profile=profile, options=step.options):
                return True
        return False

    def _elevate(self) -> bool:
        self.notify("This workflow has root steps — authenticating with sudo…")
        with self.app.suspend():
            result = subprocess.run(["sudo", "-v"], check=False)  # noqa: S603,S607
        if result.returncode != 0:
            self.notify("sudo authentication failed; launch cancelled.", severity="error")
            return False
        return True
