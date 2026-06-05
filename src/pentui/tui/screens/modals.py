"""Modal dialogs (PROJECT.md §10)."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static


class ScopeBlockModal(ModalScreen[bool]):
    """Confirm whether to override out-of-scope targets for a manual run.

    Dismisses with ``True`` if the operator overrides (the caller logs it to the
    audit log), ``False`` to cancel.
    """

    DEFAULT_CSS = """
    ScopeBlockModal { align: center middle; }
    #dialog {
        width: 70; height: auto; padding: 1 2;
        border: thick $error; background: $surface;
    }
    #title { text-style: bold; color: $error; }
    #blocked { color: $warning; padding: 1 0; }
    Horizontal { height: auto; align: center middle; }
    Button { margin: 1 1 0 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, blocked: list[str]) -> None:
        super().__init__()
        self.blocked = blocked

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("⛔ Out-of-scope targets", id="title")
            yield Static("\n".join(self.blocked), id="blocked")
            yield Static(
                "These targets are outside the engagement scope. Overriding will "
                "scan them anyway and record the override in the audit log."
            )
            with Horizontal():
                yield Button("Override (logged)", variant="error", id="override")
                yield Button("Cancel", variant="primary", id="cancel")

    @on(Button.Pressed, "#override")
    def _override(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(False)
