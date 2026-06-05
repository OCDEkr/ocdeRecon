"""The Textual application shell.

Phase 1: loads the tool registry and opens the tool-config screen so an operator
can build and run a single command, watching output live. Project selection,
the workflow builder/monitor, results, and reporting arrive in later phases
(see PROJECT.md §11, §16).
"""

from __future__ import annotations

from textual.app import App

from pentui.config import AppConfig
from pentui.core.registry import build_registry
from pentui.persistence.engagement import Engagement, open_engagement
from pentui.tui.screens.tool_config import ToolConfigScreen


class PentuiApp(App[None]):
    """Root application."""

    TITLE = "pentui"
    SUB_TITLE = "offensive-security automation TUI"

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self.config = config or AppConfig()
        self.engagement: Engagement | None = None

    def on_mount(self) -> None:
        self.engagement = open_engagement(self.config)
        registry = build_registry(self.config.user_tools_dir)
        for error in registry.errors:
            self.notify(error, severity="error", title="Manifest error", timeout=10)
        self.push_screen(ToolConfigScreen(registry, self.engagement, self.config))


def run() -> None:
    PentuiApp().run()
