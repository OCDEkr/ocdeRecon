"""Results browser screen (PROJECT.md §11).

A tree of the unified model — hosts → ports → service — plus a findings table,
read from the engagement DB. Phase 2: read-only view of what scans discovered.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Tree

from pentui.core.models import Port
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import (
    FindingRepository,
    HostRepository,
    PortRepository,
)


class ResultsScreen(Screen[None]):
    """Browse hosts/ports/services and findings for the engagement."""

    DEFAULT_CSS = """
    ResultsScreen { layout: vertical; }
    #hosts { height: 2fr; border: round $panel; margin: 0 1; }
    #findings { height: 1fr; border: round $panel; margin: 0 1; }
    .empty { padding: 1; color: $text-muted; }
    """

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, engagement: Engagement) -> None:
        super().__init__()
        self.engagement = engagement

    def compose(self) -> ComposeResult:
        yield Header()
        yield Tree("Hosts", id="hosts")
        yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_hosts()
        self._populate_findings()

    def _populate_hosts(self) -> None:
        conn = self.engagement.conn
        ports_repo = PortRepository(conn)
        tree = self.query_one("#hosts", Tree)
        tree.root.expand()
        hosts = HostRepository(conn).list_for_project(self.engagement.project_id)
        if not hosts:
            tree.root.add_leaf("(no hosts yet — run a scan)")
            return
        for host in hosts:
            label = host.ip if not host.hostname else f"{host.ip} ({host.hostname})"
            node = tree.root.add(f"{label}  [{host.state}]", expand=True)
            assert host.id is not None
            for port in ports_repo.list_for_host(host.id):
                node.add_leaf(self._port_label(port))

    @staticmethod
    def _port_label(port: Port) -> str:
        svc = port.service
        svc_text = ""
        if svc is not None:
            parts = [p for p in (svc.name, svc.product, svc.version) if p]
            svc_text = "  " + " ".join(parts)
        return f"{port.number}/{port.protocol}  {port.state}{svc_text}"

    def _populate_findings(self) -> None:
        conn = self.engagement.conn
        table = self.query_one("#findings", DataTable)
        table.add_columns("Host", "Severity", "Source", "Title")
        project_id = self.engagement.project_id
        hosts = {h.id: h.ip for h in HostRepository(conn).list_for_project(project_id)}
        findings = FindingRepository(conn).list_for_project(project_id)
        for finding in findings:
            table.add_row(
                hosts.get(finding.host_id, "-"),
                finding.severity.value,
                finding.source_tool,
                finding.title,
            )
        if not findings:
            table.add_row("-", "-", "-", "(no findings yet)")
