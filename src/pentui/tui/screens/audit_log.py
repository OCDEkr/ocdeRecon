"""Audit log viewer (PROJECT.md §10, §14).

Read-only view of the engagement's audit trail: scope overrides/skips, privilege
elevation (sudo), and workflow gate auto-approvals — the accountability record
for authorized testing.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import AuditLogRepository


class AuditLogScreen(Screen[None]):
    """Browse the engagement's audit log."""

    DEFAULT_CSS = """
    AuditLogScreen { layout: vertical; }
    DataTable { height: 1fr; margin: 0 1; }
    """

    BINDINGS = [("escape", "app.pop_screen", "Back"), ("q", "quit", "Quit")]

    def __init__(self, engagement: Engagement) -> None:
        super().__init__()
        self.engagement = engagement

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="audit")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#audit", DataTable)
        table.add_columns("Timestamp", "Action", "Detail")
        entries = AuditLogRepository(self.engagement.conn).list_for_project(
            self.engagement.project_id
        )
        for ts, action, detail in entries:
            table.add_row(ts, action, detail or "")
        if not entries:
            table.add_row("-", "(no audit entries yet)", "")
