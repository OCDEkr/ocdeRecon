"""The Textual application shell.

Loads the tool registry and opens the engagement-selection screen. From there:
engagement → dashboard → tool config / workflows / results / export. F2 toggles
between the default and colour-blind-safe themes (PROJECT.md §11, §14).
"""

from __future__ import annotations

from textual.app import App

from pentui.config import AppConfig
from pentui.core.registry import build_registry
from pentui.persistence.engagement import Engagement
from pentui.tui.screens.project_select import ProjectSelectScreen
from pentui.tui.themes import DEFAULT_THEME, next_theme, register_themes


class PentuiApp(App[None]):
    """Root application."""

    TITLE = "pentui"
    SUB_TITLE = "offensive-security automation TUI"

    BINDINGS = [("f2", "toggle_theme", "Theme")]

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self.config = config or AppConfig()
        #: Set when an engagement is opened from the selection screen.
        self.engagement: Engagement | None = None

    def on_mount(self) -> None:
        register_themes(self)
        self.theme = self.config.load_settings().get("theme", DEFAULT_THEME)
        registry = build_registry(self.config.user_tools_dir)
        for error in registry.errors:
            self.notify(error, severity="error", title="Manifest error", timeout=10)
        self.push_screen(ProjectSelectScreen(self.config, registry))

    def action_toggle_theme(self) -> None:
        self.theme = next_theme(self.theme)
        settings = self.config.load_settings()
        settings["theme"] = self.theme
        self.config.save_settings(settings)
        self.notify(f"Theme: {self.theme}")


def run() -> None:
    PentuiApp().run()
