"""Settings screen (PROJECT.md §11).

The scan-output root (the "pentests" folder). Each engagement gets its own
folder under it, and each tool its own subfolder:
``<root>/<engagement>/scans/<tool>/<scan_id>``. Blank keeps scans under the XDG
data dir. Only the root is configured; the per-engagement and per-tool structure
(registry-driven) follows automatically, so tools added later need no change here.
"""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Input, Label, Static

from pentui.config import AppConfig
from pentui.core.registry import ToolRegistry


class SettingsScreen(Screen[None]):
    """Edit the scan-output root directory."""

    DEFAULT_CSS = """
    SettingsScreen { layout: vertical; }
    #body { height: 1fr; border: round $panel; margin: 0 1; padding: 1; }
    .field { height: auto; margin-bottom: 1; }
    .field Label { color: $accent; }
    .hint { color: $text-muted; }
    #controls { height: auto; padding: 0 1; }
    Button { margin: 1 1 0 0; }
    """

    BINDINGS = [
        ("escape", "app.pop_screen", "Back (discard)"),
        ("ctrl+s", "save", "Save"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, registry: ToolRegistry, config: AppConfig) -> None:
        super().__init__()
        self.registry = registry
        self.config = config

    def compose(self) -> ComposeResult:
        yield Header()
        current = self.config.output_root()
        yield VerticalScroll(
            Label("Scan output root"),
            Input(
                value=str(current) if current else "",
                placeholder="e.g. ~/pentests  (blank = default XDG data dir)",
                id="root",
            ),
            Static(self._preview(str(current) if current else ""), classes="hint", id="preview"),
            Label("Appearance"),
            Checkbox(
                "Colour-blind-safe palette",
                value=self.config.palette() == "cb",
                id="cb",
            ),
            Static(
                "Theme mode (dark/light) toggles with F2.",
                classes="hint",
            ),
            classes="field",
            id="body",
        )
        yield Horizontal(
            Button("Save", id="save", variant="primary"),
            Button("Back", id="back"),
            id="controls",
        )
        yield Footer()

    def _preview(self, root: str) -> str:
        # Show a concrete resolved path so the layout is obvious. Pick any tool
        # name just to illustrate the per-engagement / per-tool structure.
        sample = self.registry.names()[0] if self.registry.names() else "nmap"
        base = root.strip().rstrip("/") if root.strip() else "<xdg-data>/engagements"
        return f"→ {base}/<engagement>/scans/{sample}/<scan_id>"

    @on(Input.Changed, "#root")
    def _live_preview(self, event: Input.Changed) -> None:
        self.query_one("#preview", Static).update(self._preview(event.value))

    @on(Checkbox.Changed, "#cb")
    def _toggle_palette(self, event: Checkbox.Changed) -> None:
        # Persist and apply live so the operator sees the palette change at once.
        self.config.set_palette("cb" if event.value else "standard")
        from pentui.app import PentuiApp

        if isinstance(self.app, PentuiApp):
            self.app.apply_theme()

    def action_save(self) -> None:
        """Keyboard shortcut (Ctrl+S) for the Save button."""
        self._save()

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        self.config.set_output_root(self.query_one("#root", Input).value)
        self.config.set_palette("cb" if self.query_one("#cb", Checkbox).value else "standard")
        self.notify("Settings saved.")
        self.app.pop_screen()

    @on(Button.Pressed, "#back")
    def _back(self) -> None:
        self.app.pop_screen()
