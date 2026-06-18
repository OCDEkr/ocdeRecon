"""Stats screen (PROJECT.md §11).

An at-a-glance aggregate of everything every tool has collected for the
engagement — totals, findings by severity/tool, top ports/services, SMB-signing
posture, domain controllers, and scans by tool — read from the engagement DB.
Press ``x`` to export the full data + stats as XML for an external dashboard.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, cast

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from pentui.persistence.engagement import Engagement
from pentui.reporting.exporter import (
    EngagementStats,
    ReportData,
    ReportFormat,
    compute_stats,
    export,
    gather_report,
)

if TYPE_CHECKING:
    from pentui.app import PentuiApp


class _NavDataTable(DataTable[str]):
    """A DataTable that releases focus to the adjacent focusable widget when the
    cursor would move past its top/bottom edge, so the up/down arrows flow
    continuously across the stacked stat tables on :class:`ResultsScreen`."""

    def action_cursor_up(self) -> None:
        if self.cursor_coordinate.row == 0:
            prev = self.screen.focus_previous(DataTable)
            if isinstance(prev, DataTable) and prev.row_count:
                prev.move_cursor(row=prev.row_count - 1)
        else:
            super().action_cursor_up()

    def action_cursor_down(self) -> None:
        if self.cursor_coordinate.row >= self.row_count - 1:
            nxt = self.screen.focus_next(DataTable)
            if isinstance(nxt, DataTable) and nxt.row_count:
                nxt.move_cursor(row=0)
        else:
            super().action_cursor_down()


class ResultsScreen(Screen[None]):
    """Aggregate stats for the engagement, with XML export."""

    DEFAULT_CSS = """
    ResultsScreen { layout: vertical; }
    #stats { height: 1fr; }
    #overview { height: auto; border: round $panel; margin: 0 1; padding: 0 1; }
    .empty { padding: 1; color: $text-muted; }
    .stat-table { height: auto; margin: 0 1 1 1; border: round $panel; }
    .stat-title { padding: 0 1; color: $text-muted; text-style: bold; }
    """

    BINDINGS = [
        ("x", "export_xml", "Export XML"),
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, engagement: Engagement) -> None:
        super().__init__()
        self.engagement = engagement

    def compose(self) -> ComposeResult:
        yield Header()
        yield VerticalScroll(id="stats")
        yield Footer()

    def on_mount(self) -> None:
        data = gather_report(self.engagement.conn, self.engagement.project_id)
        self._populate(data, compute_stats(data))

    def _populate(self, data: ReportData, stats: EngagementStats) -> None:
        container = self.query_one("#stats", VerticalScroll)
        container.mount(Static(self._overview_text(data, stats), id="overview"))

        if stats.is_empty:
            container.mount(Static("(no data yet — run a scan)", classes="empty"))
            return

        self._mount_table(
            container,
            "Findings by severity",
            ("Severity", "Count"),
            [(sev, str(n)) for sev, n in stats.findings_by_severity],
        )
        self._mount_table(
            container,
            "Findings by tool",
            ("Tool", "Count"),
            [(tool, str(n)) for tool, n in stats.findings_by_tool],
        )
        self._mount_table(
            container,
            "Top open ports",
            ("Port", "Hosts"),
            [(f"{num}/{proto}", str(n)) for num, proto, n in stats.top_ports],
        )
        self._mount_table(
            container,
            "Top services",
            ("Service", "Count"),
            [(name, str(n)) for name, n in stats.top_services],
        )
        self._mount_table(
            container,
            "SMB signing posture",
            ("State", "Hosts"),
            [(state, str(n)) for state, n in stats.smb_signing],
        )
        self._mount_table(
            container,
            "Scans by tool",
            ("Tool", "Total", "Breakdown"),
            [
                (
                    e.tool,
                    str(e.total),
                    ", ".join(f"{s}: {c}" for s, c in e.by_status.items()),
                )
                for e in stats.scans_by_tool
            ],
        )

        dcs = stats.domain_controllers
        dc_text = (
            "\n".join(f"  • {ip}" + (f" ({hn})" if hn else "") for ip, hn in dcs)
            if dcs
            else "  none identified"
        )
        container.mount(Static("Domain controllers", classes="stat-title"))
        container.mount(Static(dc_text, classes="stat-table"))

    def _mount_table(
        self,
        container: VerticalScroll,
        title: str,
        columns: tuple[str, ...],
        rows: list[tuple[str, ...]],
    ) -> None:
        container.mount(Static(title, classes="stat-title"))
        table: DataTable[str] = _NavDataTable(classes="stat-table")
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns(*columns)
        if rows:
            for row in rows:
                table.add_row(*row)
        else:
            table.add_row(*(["—"] * len(columns)))
        container.mount(table)

    def _overview_text(self, data: ReportData, stats: EngagementStats) -> str:
        client = data.project.client or "—"
        scope_line = (
            f"in: {', '.join(data.includes) or '—'}"
            + (f"   out: {', '.join(data.excludes)}" if data.excludes else "")
            if (data.includes or data.excludes)
            else "[yellow]no scope defined[/yellow]"
        )
        window = (
            f"{data.date_start} → {data.date_end}" if data.date_start and data.date_end else "—"
        )
        return (
            f"[b]{self.engagement.name}[/b]   client: {client}\n"
            f"scope: {scope_line}\n"
            f"targets: {', '.join(data.targets) or '—'}\n"
            f"activity: {window}\n"
            f"[b]{stats.hosts}[/b] hosts ({stats.hosts_up} up)   "
            f"[b]{stats.open_ports}[/b] open ports   "
            f"[b]{stats.services}[/b] services   "
            f"[b]{stats.findings}[/b] findings   "
            f"[b]{stats.scans}[/b] scans   "
            f"[b]{stats.workflow_runs}[/b] workflow runs"
            "   ([b]x[/b] to export XML)"
        )

    def action_export_xml(self) -> None:
        config = cast("PentuiApp", self.app).config
        reports_dir = config.reports_dir(self.engagement.name)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = reports_dir / f"stats-{stamp}.{ReportFormat.XML.extension}"
        written = export(self.engagement.conn, self.engagement.project_id, ReportFormat.XML, path)
        self.notify(f"Exported XML: {written}")
