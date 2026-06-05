"""Scan monitor screen (PROJECT.md §11).

Phase 1: run one command and stream its merged stdout/stderr live into a log
pane, teeing to disk via the executor. Concurrent-scan tabs and per-step views
arrive with the workflow engine in Phase 4.
"""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static

from pentui.core.executor import ExecutorError, preview, run_command


class ScanMonitorScreen(Screen[None]):
    """Live output for a single running command."""

    DEFAULT_CSS = """
    ScanMonitorScreen { layout: vertical; }
    #cmd { color: $text-muted; padding: 0 1; }
    #status { padding: 0 1; text-style: bold; }
    RichLog { height: 1fr; border: round $panel; margin: 0 1; }
    """

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, argv: list[str], scan_dir: str) -> None:
        super().__init__()
        self.argv = argv
        self.scan_dir = scan_dir

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(preview(self.argv), id="cmd")
        yield Static("Running…", id="status")
        yield RichLog(highlight=False, markup=False, wrap=True, id="output")
        yield Footer()

    def on_mount(self) -> None:
        self._run()

    def _emit(self, line: str) -> None:
        self.query_one("#output", RichLog).write(line)

    @work(exclusive=True)
    async def _run(self) -> None:
        status = self.query_one("#status", Static)
        try:
            result = await run_command(self.argv, scan_dir=self.scan_dir, on_line=self._emit)
        except ExecutorError as exc:
            status.update(f"[red]Failed: {exc}[/red]")
            return
        if result.exit_code == 0:
            status.update("[green]Done (exit 0)[/green]")
        else:
            status.update(f"[yellow]Exited with code {result.exit_code}[/yellow]")
