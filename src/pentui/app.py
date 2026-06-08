"""The Textual application shell.

Loads the tool registry and opens the engagement-selection screen. From there:
engagement → dashboard → tool config / workflows / results / export. F2 toggles
between the default and colour-blind-safe themes (PROJECT.md §11, §14).
"""

from __future__ import annotations

import asyncio

from textual.app import App

from pentui.config import AppConfig
from pentui.core.registry import build_registry
from pentui.persistence.engagement import Engagement
from pentui.tui.screens.modals import TextPromptModal
from pentui.tui.screens.project_select import ProjectSelectScreen
from pentui.tui.themes import DEFAULT_THEME, next_theme, register_themes


class PentuiApp(App[None]):
    """Root application."""

    TITLE = "pentui"
    SUB_TITLE = "offensive-security automation TUI"

    BINDINGS = [
        ("f2", "toggle_theme", "Theme"),
        ("f3", "clear_sudo", "Clear sudo"),
    ]

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self.config = config or AppConfig()
        #: Set when an engagement is opened from the selection screen.
        self.engagement: Engagement | None = None
        #: Operator's sudo password, captured once per session for root tools.
        self.sudo_password: str | None = None

    def on_mount(self) -> None:
        register_themes(self)
        self.theme = self.config.load_settings().get("theme", DEFAULT_THEME)
        registry = build_registry(self.config.user_tools_dir)
        for error in registry.errors:
            self.notify(error, severity="error", title="Manifest error", timeout=10)
        self.push_screen(ProjectSelectScreen(self.config, registry))

    async def request_sudo_password(self) -> str | None:
        """Return the cached sudo password, prompting (and validating) if needed.

        Returns None if the operator cancels or the password is wrong. Must be
        called from a worker (it awaits a modal).
        """
        if self.sudo_password is not None:
            return self.sudo_password
        password = await self.push_screen_wait(
            TextPromptModal("Sudo password (needed for root tools):", password=True)
        )
        if not password:
            return None
        if not await self._validate_sudo(password):
            self.notify("Incorrect sudo password.", severity="error")
            return None
        self.sudo_password = password
        return password

    @staticmethod
    async def _validate_sudo(password: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo", "-S", "-k", "-p", "", "true",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return False
        await proc.communicate((password + "\n").encode())
        return proc.returncode == 0

    def action_clear_sudo(self) -> None:
        if self.sudo_password is None:
            self.notify("No sudo password is cached.")
        else:
            self.sudo_password = None
            self.notify("Sudo password cleared.")

    def action_toggle_theme(self) -> None:
        self.theme = next_theme(self.theme)
        settings = self.config.load_settings()
        settings["theme"] = self.theme
        self.config.save_settings(settings)
        self.notify(f"Theme: {self.theme}")


def run() -> None:
    PentuiApp().run()
