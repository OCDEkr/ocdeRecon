"""The Textual application shell.

Loads the tool registry and opens the engagement-selection screen. From there:
engagement → dashboard → tool config / results. The workflow builder/monitor and
reporting arrive in later phases (see PROJECT.md §11, §16).
"""

from __future__ import annotations

from textual.app import App

from pentui.config import AppConfig
from pentui.core.registry import build_registry
from pentui.persistence.engagement import Engagement
from pentui.tui.screens.project_select import ProjectSelectScreen


class PentuiApp(App[None]):
    """Root application."""

    TITLE = "pentui"
    SUB_TITLE = "offensive-security automation TUI"

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self.config = config or AppConfig()
        #: Set when an engagement is opened from the selection screen.
        self.engagement: Engagement | None = None

    def on_mount(self) -> None:
        registry = build_registry(self.config.user_tools_dir)
        for error in registry.errors:
            self.notify(error, severity="error", title="Manifest error", timeout=10)
        self.push_screen(ProjectSelectScreen(self.config, registry))


def run() -> None:
    PentuiApp().run()
