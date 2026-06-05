"""The Textual application shell.

Phase 0 placeholder: a single screen confirming the app launches. Screens for
project selection, tool config, the workflow builder/monitor, results, and
reporting arrive in later phases (see PROJECT.md §11, §16).
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, Static

from pentui import __version__


class PentuiApp(App[None]):
    """Root application."""

    TITLE = "pentui"
    SUB_TITLE = "offensive-security automation TUI"

    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            f"pentui {__version__} — Phase 0 skeleton.\n"
            "Engine, workflows, and screens land in later phases (see PROJECT.md).",
            id="placeholder",
        )
        yield Footer()


def run() -> None:
    PentuiApp().run()
