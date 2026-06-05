"""Engagement selection / creation (PROJECT.md §11).

An engagement is one SQLite file under the data dir (one ``project`` row inside).
This screen lists existing engagements and creates new ones with their scope
rules and initial targets — the scope is the guardrail every later scan checks.
"""

from __future__ import annotations

import re
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

if TYPE_CHECKING:
    from pentui.app import PentuiApp

_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
_SPLIT = re.compile(r"[\s,]+")


def _split(value: str) -> list[str]:
    return [v for v in _SPLIT.split(value.strip()) if v]


class ProjectSelectScreen(Screen[None]):
    """Pick an existing engagement or create a new one."""

    DEFAULT_CSS = """
    ProjectSelectScreen { layout: vertical; }
    #existing { height: 1fr; border: round $panel; margin: 0 1; }
    #new { height: auto; border: round $panel; margin: 0 1; padding: 0 1; }
    .field { height: auto; margin-bottom: 1; }
    Label { padding: 1 0 0 0; }
    """

    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self, config: AppConfig, registry: ToolRegistry) -> None:
        super().__init__()
        self.config = config
        self.registry = registry

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("Open an engagement:")
        existing = self._existing_engagements()
        yield ListView(
            *[ListItem(Label(name), name=name) for name in existing],
            id="existing",
        )
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
        if not self._existing_engagements():
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
            self.notify("An engagement with that name already exists.", severity="error")
            return
        self._open(name, create=True)

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
