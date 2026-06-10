"""The Textual application shell.

Loads the tool registry and opens the engagement-selection screen. From there:
engagement → dashboard → tool config / workflows / results / export. F2 toggles
between the dark (default) and light theme modes; the colour-blind-safe accent
palette is toggled from the Settings screen (PROJECT.md §11, §14).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import cast

from textual.app import App, SystemCommand
from textual.screen import Screen

from pentui.config import AppConfig
from pentui.core.registry import build_registry
from pentui.persistence.engagement import Engagement
from pentui.tui.screens.modals import TextPromptModal
from pentui.tui.screens.project_select import ProjectSelectScreen
from pentui.tui.themes import (
    Palette,
    ThemeMode,
    flip_mode,
    register_themes,
    resolve_theme,
)


class PentuiApp(App[None]):
    """Root application."""

    TITLE = "pentui"
    SUB_TITLE = "offensive-security automation TUI"

    BINDINGS = [
        ("f1", "show_help_panel", "Help"),
        ("f2", "toggle_theme", "Light/Dark"),
        ("f3", "clear_sudo", "Clear sudo"),
        ("ctrl+d", "dashboard", "Dashboard"),
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
        self.apply_theme()
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
                "sudo",
                "-S",
                "-k",
                "-p",
                "",
                "true",
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

    def apply_theme(self) -> None:
        """Set the active theme from the persisted (mode, palette) settings."""
        mode = cast(ThemeMode, self.config.theme_mode())
        palette = cast(Palette, self.config.palette())
        self.theme = resolve_theme(mode, palette)

    def action_toggle_theme(self) -> None:
        mode = flip_mode(cast(ThemeMode, self.config.theme_mode()))
        self.config.set_theme_mode(mode)
        self.apply_theme()
        self.notify(f"Theme: {mode}")

    def _has_dashboard(self) -> bool:
        from pentui.tui.screens.dashboard import DashboardScreen

        return any(isinstance(s, DashboardScreen) for s in self.screen_stack)

    def action_dashboard(self) -> None:
        """Jump back to the engagement dashboard from any nested screen."""
        from pentui.tui.screens.dashboard import DashboardScreen

        if not self._has_dashboard():
            return
        while not isinstance(self.screen, DashboardScreen):
            self.pop_screen()

    def get_system_commands(self, screen: Screen[object]) -> Iterable[SystemCommand]:
        """Add pentui actions to the command palette (Ctrl+P) on every screen."""
        yield from super().get_system_commands(screen)
        if self._has_dashboard():
            yield SystemCommand(
                "Dashboard", "Return to the engagement dashboard", self.action_dashboard
            )
        yield SystemCommand(
            "Toggle light/dark", "Switch between the dark and light theme", self.action_toggle_theme
        )


def run() -> None:
    PentuiApp().run()
