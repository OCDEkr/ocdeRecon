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
        nessus = self.config.nessus_settings()
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
            Label("Nessus (local REST API)"),
            Input(
                value=nessus.url,
                placeholder="https://localhost:8834",
                id="nessus_url",
            ),
            Input(
                password=True,
                placeholder=self._key_placeholder(nessus.access_key, "access key"),
                id="nessus_access_key",
            ),
            Input(
                password=True,
                placeholder=self._key_placeholder(nessus.secret_key, "secret key"),
                id="nessus_secret_key",
            ),
            Static(
                "Generate keys in Nessus → Settings → My Account → API Keys. "
                "Leave a key blank to keep the stored one. Env vars (NESSUS_*) "
                "override these.",
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

    def _key_placeholder(self, stored: str | None, label: str) -> str:
        # Never echo a stored secret back into a widget; show only that one
        # exists so a blank field on save means "keep the stored key".
        return "•••• stored — blank keeps it" if stored else f"paste {label}"

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
        self._save_nessus()
        self.notify("Settings saved.")
        self.app.pop_screen()

    def _save_nessus(self) -> None:
        # Only persist fields the operator actually typed: a blank key field
        # keeps the stored key (set_nessus_settings ignores None args).
        url = self.query_one("#nessus_url", Input).value.strip()
        access = self.query_one("#nessus_access_key", Input).value.strip()
        secret = self.query_one("#nessus_secret_key", Input).value.strip()
        self.config.set_nessus_settings(
            url=url or None,
            access_key=access or None,
            secret_key=secret or None,
        )

    @on(Button.Pressed, "#back")
    def _back(self) -> None:
        self.app.pop_screen()
