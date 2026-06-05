"""Engagement dashboard (PROJECT.md §11).

Overview of one engagement: client, scope, targets, and recent scans — plus the
launch points for a new scan and the results browser.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from pentui.config import AppConfig
from pentui.core.models import ScopeKind
from pentui.core.registry import ToolRegistry
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import (
    ProjectRepository,
    ScanRepository,
    ScopeRuleRepository,
    TargetRepository,
)


class DashboardScreen(Screen[None]):
    """Per-engagement overview and launch point."""

    DEFAULT_CSS = """
    DashboardScreen { layout: vertical; }
    #summary { height: auto; border: round $panel; margin: 0 1; padding: 0 1; }
    #scans { height: 1fr; border: round $panel; margin: 0 1; }
    """

    BINDINGS = [
        ("n", "new_scan", "New scan"),
        ("w", "workflows", "Workflows"),
        ("r", "results", "Results"),
        ("e", "export", "Export"),
        ("escape", "app.pop_screen", "Engagements"),
        ("q", "quit", "Quit"),
    ]

    def __init__(
        self, engagement: Engagement, registry: ToolRegistry, config: AppConfig
    ) -> None:
        super().__init__()
        self.engagement = engagement
        self.registry = registry
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        yield VerticalScroll(Static(id="summary"))
        yield DataTable(id="scans")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#summary", Static).update(self._summary_text())
        table = self.query_one("#scans", DataTable)
        table.add_columns("Scan", "Tool", "Profile", "Status", "Exit", "Root")
        scans = ScanRepository(self.engagement.conn).list_recent(self.engagement.project_id)
        for scan in scans:
            table.add_row(
                str(scan.id),
                scan.tool,
                scan.profile or "-",
                scan.status.value,
                "-" if scan.exit_code is None else str(scan.exit_code),
                "yes" if scan.ran_as_root else "no",
            )
        if not scans:
            table.add_row("-", "(no scans yet — press n)", "-", "-", "-", "-")

    def _summary_text(self) -> str:
        conn = self.engagement.conn
        pid = self.engagement.project_id
        project = ProjectRepository(conn).get(pid)
        rules = ScopeRuleRepository(conn).list_for_project(pid)
        includes = [r.value for r in rules if r.kind is ScopeKind.INCLUDE]
        excludes = [r.value for r in rules if r.kind is ScopeKind.EXCLUDE]
        targets = [t.value for t in TargetRepository(conn).list_for_project(pid)]
        client = project.client if project and project.client else "—"
        scope_line = (
            f"in: {', '.join(includes) or '—'}"
            + (f"   out: {', '.join(excludes)}" if excludes else "")
            if rules
            else "[yellow]no scope defined — scans run without a guardrail[/yellow]"
        )
        return (
            f"[b]{self.engagement.name}[/b]   client: {client}\n"
            f"scope: {scope_line}\n"
            f"targets: {', '.join(targets) or '—'}"
        )

    def action_new_scan(self) -> None:
        from pentui.tui.screens.tool_config import ToolConfigScreen

        self.app.push_screen(
            ToolConfigScreen(self.registry, self.engagement, self.config)
        )

    def action_workflows(self) -> None:
        from pentui.tui.screens.workflow_launch import WorkflowLaunchScreen

        self.app.push_screen(
            WorkflowLaunchScreen(self.engagement, self.registry, self.config)
        )

    def action_results(self) -> None:
        from pentui.tui.screens.results import ResultsScreen

        self.app.push_screen(ResultsScreen(self.engagement))

    def action_export(self) -> None:
        from pentui.tui.screens.report_export import ReportExportScreen

        self.app.push_screen(ReportExportScreen(self.engagement, self.config))
