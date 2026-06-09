"""Shared helpers for driving the TUI in tests."""

from __future__ import annotations

from textual.widgets import Input


async def start_engagement(
    pilot,
    *,
    name: str = "test",
    client: str = "",
    includes: str = "",
    excludes: str = "",
    targets: str = "",
    open_scan: bool = True,
) -> None:
    """From the project-select screen, create an engagement.

    With ``open_scan`` (default) it presses 'n' to leave the app on the
    ToolConfigScreen; otherwise it stops on the DashboardScreen.
    """
    app = pilot.app
    app.screen.query_one("#name", Input).value = name
    app.screen.query_one("#client", Input).value = client
    app.screen.query_one("#includes", Input).value = includes
    app.screen.query_one("#excludes", Input).value = excludes
    app.screen.query_one("#targets", Input).value = targets
    await pilot.pause()
    await pilot.click("#create")
    await pilot.pause()
    if open_scan:
        await pilot.press("n")
        await pilot.pause()
