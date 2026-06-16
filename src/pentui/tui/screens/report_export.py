"""Report export screen (PROJECT.md §11, §12).

Pick one or more formats and generate reports for the engagement. Files are
written under the engagement's ``reports/`` directory and the paths are shown.
"""

from __future__ import annotations

from datetime import datetime

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Label, RichLog

from pentui.config import AppConfig
from pentui.persistence.engagement import Engagement
from pentui.reporting.exporter import ReportFormat, export


class ReportExportScreen(Screen[None]):
    """Choose formats and export engagement reports."""

    DEFAULT_CSS = """
    ReportExportScreen { layout: vertical; }
    #formats { height: auto; border: round $panel; margin: 0 1; padding: 0 1; }
    #out { height: 1fr; border: round $panel; margin: 0 1; }
    #controls { height: auto; padding: 0 1; }
    """

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("ctrl+e", "export", "Export"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, engagement: Engagement, config: AppConfig) -> None:
        super().__init__()
        self.engagement = engagement
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="formats"):
            yield Label("Formats to export:")
            yield Checkbox("Markdown", value=True, id="fmt-markdown")
            yield Checkbox("HTML", value=True, id="fmt-html")
            yield Checkbox("JSON", id="fmt-json")
            yield Checkbox("CSV (host/port/service inventory)", id="fmt-csv")
            yield Checkbox("XML (full data + stats)", id="fmt-xml")
        yield Horizontal(Button("Export", variant="primary", id="export"), id="controls")
        yield RichLog(highlight=False, markup=False, wrap=True, id="out")
        yield Footer()

    def _selected_formats(self) -> list[ReportFormat]:
        chosen = []
        for fmt in ReportFormat:
            if self.query_one(f"#fmt-{fmt.value}", Checkbox).value:
                chosen.append(fmt)
        return chosen

    def action_export(self) -> None:
        """Keyboard shortcut (Ctrl+E) for the Export button."""
        self._export()

    @on(Button.Pressed, "#export")
    def _export(self) -> None:
        formats = self._selected_formats()
        out = self.query_one("#out", RichLog)
        if not formats:
            self.notify("Select at least one format.", severity="warning")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        reports_dir = self.config.reports_dir(self.engagement.name)
        for fmt in formats:
            path = reports_dir / f"report-{stamp}.{fmt.extension}"
            written = export(self.engagement.conn, self.engagement.project_id, fmt, path)
            out.write(f"✓ {fmt.value}: {written}")
        self.notify(f"Exported {len(formats)} report(s).")
