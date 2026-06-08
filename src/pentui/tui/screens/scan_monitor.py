"""Scan monitor screen (PROJECT.md §11).

Runs one or more commands (a batch-over-directory expands to several), streaming
merged stdout/stderr live and teeing to an aggregate ``stdout.log``. For a single
run of a tool with a parser, the artifact is parsed into the unified model. Stop
with ``s`` (terminates the running process; remaining batch items are skipped).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TextIO

from textual import work
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static

from pentui.core.executor import (
    ExecutorError,
    Process,
    preview,
    run_command,
    terminate_process,
)
from pentui.core.manifest import ToolManifest
from pentui.core.models import Scan, ScanStatus
from pentui.parsers import get_parser
from pentui.parsers.base import ParseContext
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import ScanRepository
from pentui.persistence.store import merge_scan_result


class ScanMonitorScreen(Screen[None]):
    """Live output + result persistence for a scan (one or many commands)."""

    DEFAULT_CSS = """
    ScanMonitorScreen { layout: vertical; }
    #cmd { color: $text-muted; padding: 0 1; }
    #status { padding: 0 1; text-style: bold; }
    RichLog { height: 1fr; border: round $panel; margin: 0 1; }
    """

    BINDINGS = [
        ("s", "stop", "Stop"),
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
        runs: list[tuple[str, list[str]]],
        *,
        sudo_password: str | None = None,
    ) -> None:
        super().__init__()
        self.engagement = engagement
        self.manifest = manifest
        self.scan = scan
        self.scan_dir = scan_dir
        self.runs = runs
        self.sudo_password = sudo_password
        self._proc: Process | None = None
        self._stopped = False
        self._log: TextIO | None = None

    def action_stop(self) -> None:
        self._stopped = True
        if self._proc is not None and self._proc.returncode is None:
            self.query_one("#status", Static).update("[yellow]Stopping…[/yellow]")
            terminate_process(self._proc)
        else:
            self.notify("Nothing running to stop.", severity="warning")

    def compose(self) -> ComposeResult:
        first = preview(self.runs[0][1]) if self.runs else ""
        extra = f"   (+{len(self.runs) - 1} more files)" if len(self.runs) > 1 else ""
        yield Header()
        yield Static(first + extra, id="cmd")
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
        if self._log is not None:
            self._log.write(line + "\n")

    def _on_proc(self, proc: Process) -> None:
        self._proc = proc

    @work(exclusive=True)
    async def _run(self) -> None:
        status = self.query_one("#status", Static)
        scans = ScanRepository(self.engagement.conn)
        self.scan.status = ScanStatus.RUNNING
        self.scan.started_at = datetime.now()
        scans.update(self.scan)

        log_path = Path(self.scan_dir) / "stdout.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = log_path.open("w", encoding="utf-8")
        exit_codes: list[int] = []
        try:
            for index, (label, argv) in enumerate(self.runs):
                if self._stopped:
                    break
                if label:
                    self._emit(f"=== [{index + 1}/{len(self.runs)}] {label} ===")
                try:
                    result = await run_command(
                        argv, on_line=self._emit, on_start=self._on_proc,
                        stdin_data=self.sudo_password,
                    )
                except ExecutorError as exc:
                    self._emit(f"✗ {exc}")
                    exit_codes.append(127)
                    continue
                exit_codes.append(result.exit_code)
                if result.stopped:
                    self._stopped = True
                    break
        finally:
            self._log.close()
            self._log = None

        self.scan.raw_output_path = str(log_path)
        self.scan.exit_code = exit_codes[-1] if exit_codes else None
        self.scan.finished_at = datetime.now()

        if self._stopped:
            self.scan.status = ScanStatus.CANCELLED
            scans.update(self.scan)
            status.update("[yellow]Stopped[/yellow]")
            return

        ok = all(code == 0 for code in exit_codes)
        self.scan.status = ScanStatus.DONE if ok else ScanStatus.ERROR
        scans.update(self.scan)
        status.update(self._summary(exit_codes, ok))

    def _summary(self, exit_codes: list[int], ok: bool) -> str:
        if len(self.runs) > 1:
            passed = sum(1 for c in exit_codes if c == 0)
            colour = "green" if ok else "yellow"
            return f"[{colour}]Done — {passed}/{len(self.runs)} files succeeded[/{colour}]"
        return self._persist_results() or self._exit_message()

    def _exit_message(self) -> str:
        if self.scan.exit_code == 0:
            return "[green]Done (exit 0)[/green]"
        return f"[yellow]Exited with code {self.scan.exit_code}[/yellow]"

    def _persist_results(self) -> str | None:
        """Parse + merge the artifact if the tool has a parser. Returns a summary."""
        parser_name = self.manifest.output.parser
        if not parser_name or self.scan.exit_code != 0:
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
