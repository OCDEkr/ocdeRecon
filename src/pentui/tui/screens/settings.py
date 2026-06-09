"""Settings screen (PROJECT.md §11).

Per-tool output-directory overrides. Each tool's scan output (stdout log +
artifacts) defaults to ``<engagement>/scans/<tool>/<scan_id>`` — its own folder
per engagement. Pointing a tool at a custom base relocates it to
``<base>/<engagement>/<scan_id>``, still namespaced per engagement so they never
collide. The list is driven by the tool registry, so tools added later (a new
manifest, no code) get a row here automatically.
"""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static

from pentui.config import AppConfig
from pentui.core.registry import ToolRegistry


class SettingsScreen(Screen[None]):
    """Edit per-tool output-directory overrides."""

    DEFAULT_CSS = """
    SettingsScreen { layout: vertical; }
    #tools { height: 1fr; border: round $panel; margin: 0 1; padding: 0 1; }
    #intro { color: $text-muted; padding: 0 1; }
    .field { height: auto; margin-bottom: 1; }
    .field Label { color: $accent; }
    .hint { color: $text-muted; }
    #controls { height: auto; padding: 0 1; }
    Button { margin: 1 1 0 0; }
    """

    BINDINGS = [
        ("escape", "app.pop_screen", "Back (discard)"),
        ("q", "app.quit", "Quit"),
    ]

    def __init__(self, registry: ToolRegistry, config: AppConfig) -> None:
        super().__init__()
        self.registry = registry
        self.config = config
        #: tool name -> its dir Input (avoids relying on tool names as widget ids).
        self._inputs: dict[str, Input] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "Per-tool output directory. Blank = default "
            "(<engagement>/scans/<tool>). A custom base becomes "
            "<base>/<engagement>/<scan_id>.",
            id="intro",
        )
        overrides = self.config.tool_output_dirs()
        fields = []
        for name in self.registry.names():
            box = Input(value=overrides.get(name, ""), placeholder=f"default: …/scans/{name}")
            self._inputs[name] = box
            fields.append(
                VerticalScroll(
                    Label(name),
                    box,
                    Static(f"→ {self._preview(name, overrides.get(name, ''))}", classes="hint"),
                    classes="field",
                )
            )
        yield VerticalScroll(*fields, id="tools")
        yield Horizontal(
            Button("Save", id="save", variant="primary"),
            Button("Back", id="back"),
            id="controls",
        )
        yield Footer()

    @staticmethod
    def _preview(tool: str, override: str) -> str:
        if override.strip():
            return f"{override.strip().rstrip('/')}/<engagement>/<scan_id>"
        return f"<engagement>/scans/{tool}/<scan_id>"

    @on(Input.Changed)
    def _live_preview(self, event: Input.Changed) -> None:
        # Update the hint under the changed field so the resolved path is visible.
        for name, box in self._inputs.items():
            if box is event.input:
                field = box.parent
                if field is not None:
                    field.query_one(".hint", Static).update(f"→ {self._preview(name, event.value)}")
                break

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        for name, box in self._inputs.items():
            self.config.set_tool_output_dir(name, box.value)
        self.notify("Output directories saved.")
        self.app.pop_screen()

    @on(Button.Pressed, "#back")
    def _back(self) -> None:
        self.app.pop_screen()
