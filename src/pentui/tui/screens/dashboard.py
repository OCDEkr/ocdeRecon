"""Engagement dashboard (PROJECT.md §11).

Overview of one engagement: client, scope, target/result counts, and recent
scans — plus the launch points for a new scan, workflows, results, export, and
the audit log. Refreshed whenever the screen is shown so it reflects scans run
since it was opened.
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
    FindingRepository,
    HostRepository,
    PortRepository,
    ProjectRepository,
    ScanRepository,
    ScopeRuleRepository,
    TargetRepository,
)

_SCAN_COLUMNS = ("Scan", "Tool", "Profile", "Status", "Exit", "Root")


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
        ("a", "audit", "Audit log"),
        ("escape", "app.pop_screen", "Engagements"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, engagement: Engagement, registry: ToolRegistry, config: AppConfig) -> None:
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
        self._refresh()

    def on_screen_resume(self) -> None:
        # Returning from a scan/workflow — reflect any new results.
        self._refresh()

    def _refresh(self) -> None:
        self.query_one("#summary", Static).update(self._summary_text())
        table = self.query_one("#scans", DataTable)
        if not table.columns:
            table.add_columns(*_SCAN_COLUMNS)
        table.clear()
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

        hosts = HostRepository(conn).list_for_project(pid)
        ports_repo = PortRepository(conn)
        open_ports = sum(
            1 for h in hosts for p in ports_repo.list_for_host(h.id or 0) if p.state == "open"
        )
        findings = len(FindingRepository(conn).list_for_project(pid))

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
            f"targets: {', '.join(targets) or '—'}\n"
            f"results: {len(hosts)} hosts, {open_ports} open ports, {findings} findings"
            "   ([b]r[/b] to browse)"
        )

    def action_new_scan(self) -> None:
        from pentui.tui.screens.tool_config import ToolConfigScreen

        self.app.push_screen(ToolConfigScreen(self.registry, self.engagement, self.config))

    def action_workflows(self) -> None:
        from pentui.tui.screens.workflow_launch import WorkflowLaunchScreen

        self.app.push_screen(WorkflowLaunchScreen(self.engagement, self.registry, self.config))

    def action_results(self) -> None:
        from pentui.tui.screens.results import ResultsScreen

        self.app.push_screen(ResultsScreen(self.engagement))

    def action_export(self) -> None:
        from pentui.tui.screens.report_export import ReportExportScreen

        self.app.push_screen(ReportExportScreen(self.engagement, self.config))

    def action_audit(self) -> None:
        from pentui.tui.screens.audit_log import AuditLogScreen

        self.app.push_screen(AuditLogScreen(self.engagement))
