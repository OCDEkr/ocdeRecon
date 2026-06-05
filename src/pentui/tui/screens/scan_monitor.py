"""Scan monitor screen (PROJECT.md §11).

Runs one command, streams its merged stdout/stderr live (teed to disk by the
executor), then — if the tool has a parser — parses the artifact into the unified
model and persists it, reporting a short summary. Concurrent-scan tabs arrive
with the workflow engine in Phase 4.
"""

from __future__ import annotations

from datetime import datetime

from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static

from pentui.core.executor import ExecutorError, preview, run_command
from pentui.core.manifest import ToolManifest
from pentui.core.models import Scan, ScanStatus
from pentui.parsers import get_parser
from pentui.parsers.base import ParseContext
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import ScanRepository
from pentui.persistence.store import merge_scan_result


class ScanMonitorScreen(Screen[None]):
    """Live output + result persistence for a single command."""

    DEFAULT_CSS = """
    ScanMonitorScreen { layout: vertical; }
    #cmd { color: $text-muted; padding: 0 1; }
    #status { padding: 0 1; text-style: bold; }
    RichLog { height: 1fr; border: round $panel; margin: 0 1; }
    """

    BINDINGS = [
        ("r", "view_results", "Results"),
        ("escape", "app.pop_screen", "Back"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(
        self,
        engagement: Engagement,
        manifest: ToolManifest,
        scan: Scan,
        scan_dir: str,
    ) -> None:
        super().__init__()
        self.engagement = engagement
        self.manifest = manifest
        self.scan = scan
        self.scan_dir = scan_dir
        self.argv = scan.args

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(preview(self.argv), id="cmd")
        yield Static("Running…", id="status")
        yield RichLog(highlight=False, markup=False, wrap=True, id="output")
        yield Footer()

    def on_mount(self) -> None:
        self._run()

    def action_view_results(self) -> None:
        from pentui.tui.screens.results import ResultsScreen

        self.app.push_screen(ResultsScreen(self.engagement))

    def _emit(self, line: str) -> None:
        self.query_one("#output", RichLog).write(line)

    @work(exclusive=True)
    async def _run(self) -> None:
        status = self.query_one("#status", Static)
        scans = ScanRepository(self.engagement.conn)
        self.scan.status = ScanStatus.RUNNING
        self.scan.started_at = datetime.now()
        scans.update(self.scan)

        try:
            result = await run_command(self.argv, scan_dir=self.scan_dir, on_line=self._emit)
        except ExecutorError as exc:
            self.scan.status = ScanStatus.ERROR
            self.scan.finished_at = datetime.now()
            scans.update(self.scan)
            status.update(f"[red]Failed: {exc}[/red]")
            return

        self.scan.exit_code = result.exit_code
        self.scan.raw_output_path = result.stdout_log_path
        self.scan.finished_at = datetime.now()
        self.scan.status = ScanStatus.DONE if result.exit_code == 0 else ScanStatus.ERROR
        scans.update(self.scan)

        status.update(self._persist_results() or self._exit_message())

    def _exit_message(self) -> str:
        if self.scan.exit_code == 0:
            return "[green]Done (exit 0)[/green]"
        return f"[yellow]Exited with code {self.scan.exit_code}[/yellow]"

    def _persist_results(self) -> str | None:
        """Parse + merge the artifact if the tool has a parser. Returns a summary."""
        parser_name = self.manifest.output.parser
        if not parser_name:
            return None
        parser = get_parser(parser_name)
        if parser is None:
            self.notify(f"No parser registered: {parser_name!r}", severity="warning")
            return None
        ctx = ParseContext(
            raw_stdout="",
            raw_stderr="",
            artifact_path=self.scan.artifact_path,
            scan_id=self.scan.id or 0,
            project_id=self.engagement.project_id,
        )
        result = parser(ctx)
        summary = merge_scan_result(
            self.engagement.conn, self.engagement.project_id, self.scan.id, result
        )
        return (
            f"[green]Done[/green] — {summary.hosts} hosts, "
            f"{summary.open_ports} open ports, {summary.findings} findings. "
            "Press [b]r[/b] for results."
        )
