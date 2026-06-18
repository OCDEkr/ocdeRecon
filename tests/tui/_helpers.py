"""Shared helpers for driving the TUI in tests."""

from __future__ import annotations

from textual.widgets import Input, Select


async def start_engagement(
    pilot,
    *,
    name: str = "test",
    client: str = "",
    includes: str = "",
    excludes: str = "",
    targets: str = "",
    passphrase: str = "",
    open_scan: bool = True,
    tool: str | None = None,
) -> None:
    """From the project-select screen, create an engagement.

    With ``open_scan`` (default) it presses 'n' to leave the app on the
    ToolConfigScreen; otherwise it stops on the DashboardScreen. When ``tool`` is
    given, that manifest is selected on the tool-config screen (so tests don't
    depend on which tool sorts first in the registry).
    """
    app = pilot.app
    app.screen.query_one("#name", Input).value = name
    app.screen.query_one("#client", Input).value = client
    app.screen.query_one("#includes", Input).value = includes
    app.screen.query_one("#excludes", Input).value = excludes
    app.screen.query_one("#targets", Input).value = targets
    app.screen.query_one("#passphrase", Input).value = passphrase
    await pilot.pause()
    await pilot.click("#create")
    await pilot.pause()
    if open_scan:
        await pilot.press("n")
        await pilot.pause()
        if tool is not None:
            app.screen.query_one("#tool", Select).value = tool
            await pilot.pause()
