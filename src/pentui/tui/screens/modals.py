"""Modal dialogs (PROJECT.md §10)."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static


class TextPromptModal(ModalScreen[str | None]):
    """Prompt for a single line of text. Dismisses the value, or None if cancelled."""

    DEFAULT_CSS = """
    TextPromptModal { align: center middle; }
    #dialog {
        width: 60; height: auto; padding: 1 2;
        border: thick $primary; background: $surface;
    }
    #title { text-style: bold; }
    Horizontal { height: auto; align: center middle; }
    Button { margin: 1 1 0 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, title: str, placeholder: str = "") -> None:
        super().__init__()
        self._title = title
        self._placeholder = placeholder

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, id="title")
            yield Input(placeholder=self._placeholder, id="value")
            with Horizontal():
                yield Button("Save", variant="primary", id="ok")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#value", Input).focus()

    @on(Input.Submitted, "#value")
    @on(Button.Pressed, "#ok")
    def _ok(self) -> None:
        self.dismiss(self.query_one("#value", Input).value.strip() or None)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmModal(ModalScreen[bool]):
    """Generic yes/no confirmation. Dismisses True on confirm, False otherwise."""

    DEFAULT_CSS = """
    ConfirmModal { align: center middle; }
    #dialog {
        width: 70; height: auto; padding: 1 2;
        border: thick $error; background: $surface;
    }
    #title { text-style: bold; color: $error; }
    Horizontal { height: auto; align: center middle; }
    Button { margin: 1 1 0 1; }
    """

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(
        self, title: str, message: str, *, confirm_label: str = "Delete"
    ) -> None:
        super().__init__()
        self._title = title
        self._message = message
        self._confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, id="title")
            yield Static(self._message)
            with Horizontal():
                yield Button(self._confirm_label, variant="error", id="confirm")
                yield Button("Cancel", variant="primary", id="cancel")

    @on(Button.Pressed, "#confirm")
    def _confirm(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(False)


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


class GateApproveModal(ModalScreen[bool]):
    """Workflow gate: approve a step before it runs, or skip it (and its branch)."""

    DEFAULT_CSS = """
    GateApproveModal { align: center middle; }
    #dialog {
        width: 70; height: auto; padding: 1 2;
        border: thick $warning; background: $surface;
    }
    #title { text-style: bold; color: $warning; }
    Horizontal { height: auto; align: center middle; }
    Button { margin: 1 1 0 1; }
    """

    BINDINGS = [("escape", "skip", "Skip")]

    def __init__(self, step_id: str, detail: str) -> None:
        super().__init__()
        self.step_id = step_id
        self.detail = detail

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(f"⏸ Gate: step '{self.step_id}'", id="title")
            yield Static(self.detail)
            with Horizontal():
                yield Button("Approve", variant="success", id="approve")
                yield Button("Skip", variant="warning", id="skip")

    @on(Button.Pressed, "#approve")
    def _approve(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#skip")
    def action_skip(self) -> None:
        self.dismiss(False)
