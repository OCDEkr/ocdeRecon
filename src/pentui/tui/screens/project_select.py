"""Engagement selection / creation (PROJECT.md §11).

An engagement is one SQLite file under the data dir (one ``project`` row inside).
This screen lists existing engagements, creates new ones with their scope rules
and initial targets, and deletes them (with confirmation).
"""

from __future__ import annotations

import re
import shutil
from typing import TYPE_CHECKING, cast

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, ListItem, ListView

from pentui.config import AppConfig
from pentui.core.models import ScopeKind
from pentui.core.registry import ToolRegistry
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import ScopeRuleRepository, TargetRepository
from pentui.tui.screens.modals import ConfirmModal

if TYPE_CHECKING:
    from pentui.app import PentuiApp

_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
_SPLIT = re.compile(r"[\s,]+")


def _split(value: str) -> list[str]:
    return [v for v in _SPLIT.split(value.strip()) if v]


class ProjectSelectScreen(Screen[None]):
    """Pick an existing engagement, create a new one, or delete one."""

    DEFAULT_CSS = """
    ProjectSelectScreen { layout: vertical; }
    #existing { height: 1fr; border: round $panel; margin: 0 1; }
    #new { height: auto; border: round $panel; margin: 0 1; padding: 0 1; }
    .field { height: auto; margin-bottom: 1; }
    Label { padding: 1 0 0 0; }
    """

    BINDINGS = [("d", "delete", "Delete"), ("q", "app.quit", "Quit")]

    def __init__(self, config: AppConfig, registry: ToolRegistry) -> None:
        super().__init__()
        self.config = config
        self.registry = registry

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Open an engagement (↑/↓ to select, Enter to open, d to delete):")
        # Populated by _refresh_list() on mount and whenever the screen resumes,
        # so engagements created this session show up when we return here.
        yield ListView(id="existing")
        with Vertical(id="new"):
            yield Label("New engagement")
            yield Input(placeholder="name (letters, digits, - or _)", id="name", classes="field")
            yield Input(placeholder="client (optional)", id="client", classes="field")
            yield Input(placeholder="in-scope, e.g. 10.0.0.0/24 app.example", id="includes",
                        classes="field")
            yield Input(placeholder="excludes (optional)", id="excludes", classes="field")
            yield Input(placeholder="initial targets (optional)", id="targets", classes="field")
            yield Horizontal(Button("Create & open", variant="primary", id="create"))
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_list()
        self._focus_default()

    def on_screen_resume(self) -> None:
        # Fired when returning from the dashboard — pick up newly created
        # engagements and reset the form so the previous name doesn't linger.
        self._refresh_list()
        for field in ("#name", "#client", "#includes", "#excludes", "#targets"):
            self.query_one(field, Input).value = ""
        self._focus_default()

    def _refresh_list(self) -> None:
        view = self.query_one("#existing", ListView)
        view.clear()
        for name in self._existing_engagements():
            view.append(ListItem(Label(name), name=name))

    def _focus_default(self) -> None:
        # Focus the list (so d/↑/↓/Enter work) when there are engagements;
        # otherwise focus the name field for a fresh create.
        if self._existing_engagements():
            self.query_one("#existing", ListView).focus()
        else:
            self.query_one("#name", Input).focus()

    def _existing_engagements(self) -> list[str]:
        base = self.config.engagements_dir
        if not base.is_dir():
            return []
        return sorted(d.name for d in base.iterdir() if (d / "engagement.db").exists())

    @on(ListView.Selected, "#existing")
    def _open_existing(self, event: ListView.Selected) -> None:
        if event.item.name:
            self._open(event.item.name)

    @on(Button.Pressed, "#create")
    def _create(self) -> None:
        name = self.query_one("#name", Input).value.strip()
        if not _NAME.match(name):
            self.notify("Name must be letters, digits, - or _.", severity="error")
            return
        if name in self._existing_engagements():
            self.notify(
                "That engagement already exists — select it from the list above to open it.",
                severity="error",
            )
            return
        self._open(name, create=True)

    # -- delete ------------------------------------------------------------ #
    def action_delete(self) -> None:
        view = self.query_one("#existing", ListView)
        item = view.highlighted_child
        if item is None or item.name is None:
            self.notify("No engagement selected to delete.", severity="warning")
            return
        name = item.name

        def on_confirm(confirmed: bool | None) -> None:
            if confirmed:
                self._delete(name)

        self.app.push_screen(
            ConfirmModal(
                "⚠ Delete engagement",
                f"Delete '{name}'? This removes its database, scans, and reports. "
                "This cannot be undone.",
            ),
            on_confirm,
        )

    def _delete(self, name: str) -> None:
        app = cast("PentuiApp", self.app)
        # Close the connection if this engagement happens to be the open one.
        if app.engagement is not None and app.engagement.name == name:
            app.engagement.conn.close()
            app.engagement = None
        try:
            shutil.rmtree(self.config.engagement_dir(name))
        except OSError as exc:
            self.notify(f"Could not delete '{name}': {exc}", severity="error")
            return
        self.notify(f"Deleted engagement '{name}'.")
        self._refresh_list()
        self._focus_default()

    def _open(self, name: str, *, create: bool = False) -> None:
        engagement = open_engagement(self.config, name)
        if create:
            client = self.query_one("#client", Input).value.strip()
            if client:
                engagement.conn.execute(
                    "UPDATE project SET client = ? WHERE id = ?;",
                    (client, engagement.project_id),
                )
                engagement.conn.commit()
            scopes = ScopeRuleRepository(engagement.conn)
            for value in _split(self.query_one("#includes", Input).value):
                scopes.create(engagement.project_id, value, ScopeKind.INCLUDE)
            for value in _split(self.query_one("#excludes", Input).value):
                scopes.create(engagement.project_id, value, ScopeKind.EXCLUDE)
            targets = TargetRepository(engagement.conn)
            for value in _split(self.query_one("#targets", Input).value):
                targets.create(engagement.project_id, value)

        cast("PentuiApp", self.app).engagement = engagement
        from pentui.tui.screens.dashboard import DashboardScreen

        self.app.push_screen(DashboardScreen(engagement, self.registry, self.config))
