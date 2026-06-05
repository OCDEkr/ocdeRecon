"""Tool configuration screen (PROJECT.md §11).

Phase 1: pick a tool + profile, toggle manifest-defined options, enter targets,
and see a live command preview. Launching hands off to the scan monitor. Root
elevation is confirmed here (the app suspends so ``sudo`` can prompt on the real
terminal) — core stays UI-free.
"""

from __future__ import annotations

import os
import re
import subprocess

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)

from pentui.config import AppConfig
from pentui.core.executor import ExecutorError, build_argv, preview, requires_root
from pentui.core.manifest import OptionType, ToolManifest, ToolOption, ToolProfile
from pentui.core.models import Scan
from pentui.core.registry import ToolRegistry
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import ScanRepository

_SPLIT = re.compile(r"[\s,]+")


class ToolConfigScreen(Screen[None]):
    """Configure and launch a single tool run."""

    DEFAULT_CSS = """
    ToolConfigScreen { layout: vertical; }
    #options { height: 1fr; border: round $panel; padding: 0 1; }
    #cmd { color: $text-muted; padding: 1; border: round $panel; }
    #controls { height: auto; padding: 0 1; }
    .field { height: auto; margin-bottom: 1; }
    Button { margin: 1 1 0 0; }
    """

    BINDINGS = [("q", "quit", "Quit")]

    def __init__(
        self,
        registry: ToolRegistry,
        engagement: Engagement,
        config: AppConfig | None = None,
    ) -> None:
        super().__init__()
        self.registry = registry
        self.engagement = engagement
        self.config = config or AppConfig()
        self.manifest: ToolManifest | None = registry.all()[0] if registry.all() else None
        self._option_widgets: list[tuple[ToolOption, Checkbox | Input | Select[str]]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        if self.manifest is None:
            yield Static("No tool manifests found. Add one under tools/ or "
                         "~/.config/pentui/tools/.", id="cmd")
            yield Footer()
            return
        tool_opts = [(name, name) for name in self.registry.names()]
        yield Horizontal(
            Label("Tool:"),
            Select(tool_opts, value=self.manifest.name, allow_blank=False, id="tool"),
            Label("Profile:"),
            Select(self._profile_options(), allow_blank=True, id="profile"),
            classes="field",
        )
        yield Horizontal(
            Label("Targets:"),
            Input(placeholder="e.g. 10.0.0.0/24 scanme.example", id="targets"),
            classes="field",
        )
        # Build the manifest-driven option widgets here in compose (mounting a
        # Select dynamically races with its own overlay setup, so we never do
        # that during on_mount — tool switches go through recompose() instead).
        self._option_widgets = []
        with VerticalScroll(id="options"):
            for option in self.manifest.options:
                widget = self._make_option_widget(option)
                self._option_widgets.append((option, widget))
                label = option.label + (" [root]" if option.requires_root else "")
                yield Horizontal(Label(label, classes="field"), widget)
        yield Static("", id="cmd")
        yield Horizontal(Button("Run scan", variant="primary", id="run"), id="controls")
        yield Footer()

    def on_mount(self) -> None:
        if self.manifest is not None:
            self._update_preview()

    # -- option form ------------------------------------------------------- #
    def _profile_options(self) -> list[tuple[str, str]]:
        assert self.manifest is not None
        return [(p.name, p.name) for p in self.manifest.profiles]

    def _make_option_widget(self, option: ToolOption) -> Checkbox | Input | Select[str]:
        if option.type is OptionType.BOOL:
            return Checkbox(value=False)
        if option.type is OptionType.CHOICE:
            choices = [(c, c) for c in option.choices]
            if option.default:
                return Select(choices, value=option.default, allow_blank=True)
            return Select(choices, allow_blank=True)
        return Input(placeholder=option.placeholder or "")

    # -- live preview ------------------------------------------------------ #
    def _current_profile(self) -> ToolProfile | None:
        assert self.manifest is not None
        value = self.query_one("#profile", Select).value
        return self.manifest.profile(value) if isinstance(value, str) else None

    def _current_options(self) -> dict[str, str | bool]:
        values: dict[str, str | bool] = {}
        for option, widget in self._option_widgets:
            if isinstance(widget, Checkbox):
                values[option.flag] = widget.value
            elif isinstance(widget, Select):
                if isinstance(widget.value, str):
                    values[option.flag] = widget.value
            elif widget.value:  # Input
                values[option.flag] = widget.value
        return values

    def _current_targets(self) -> list[str]:
        raw = self.query_one("#targets", Input).value.strip()
        return [t for t in _SPLIT.split(raw) if t]

    def _try_build(self, *, sudo: bool, scan_dir: str | None) -> list[str]:
        assert self.manifest is not None
        return build_argv(
            self.manifest,
            profile=self._current_profile(),
            options=self._current_options(),
            targets=self._current_targets(),
            scan_dir=scan_dir or "{scan_dir}",
            sudo=sudo,
        )

    def _update_preview(self) -> None:
        try:
            argv = self._try_build(sudo=False, scan_dir=None)
            self.query_one("#cmd", Static).update(preview(argv))
        except ExecutorError as exc:
            self.query_one("#cmd", Static).update(f"[red]⚠ {exc}[/red]")

    @on(Select.Changed, "#tool")
    async def _on_tool_changed(self, event: Select.Changed) -> None:
        # Ignore the initial Changed (value already matches the current manifest).
        if isinstance(event.value, str) and (
            self.manifest is None or event.value != self.manifest.name
        ):
            self.manifest = self.registry.get(event.value)
            await self.recompose()
            self._update_preview()

    @on(Select.Changed)
    @on(Checkbox.Changed)
    @on(Input.Changed)
    def _on_any_change(self) -> None:
        if self.manifest is not None:
            self._update_preview()

    # -- launch ------------------------------------------------------------ #
    @on(Button.Pressed, "#run")
    def _on_run(self) -> None:
        if self.manifest is None:
            return
        if not self._current_targets():
            self.notify("Enter at least one target.", severity="warning")
            return
        try:
            self._try_build(sudo=False, scan_dir=None)  # validate
        except ExecutorError as exc:
            self.notify(str(exc), severity="error", title="Invalid command")
            return

        profile = self._current_profile()
        need_root = requires_root(
            self.manifest, profile=profile, options=self._current_options()
        )
        use_sudo = need_root and os.geteuid() != 0
        if use_sudo and not self._elevate():
            return

        # Create the scan row first so the artifact/log dir keys off its id.
        scans = ScanRepository(self.engagement.conn)
        scan = scans.create(
            Scan(
                project_id=self.engagement.project_id,
                tool=self.manifest.name,
                profile=profile.name if profile else None,
                ran_as_root=use_sudo,
            )
        )
        assert scan.id is not None
        scan_dir = str(self.config.scan_dir(self.engagement.name, scan.id))
        argv = self._try_build(sudo=use_sudo, scan_dir=scan_dir)
        scan.command_str = preview(argv)
        scan.args = argv
        if self.manifest.output.artifact is not None:
            scan.artifact_path = self.manifest.output.artifact.path.format(scan_dir=scan_dir)
        scans.update(scan)

        from pentui.tui.screens.scan_monitor import ScanMonitorScreen

        self.app.push_screen(
            ScanMonitorScreen(self.engagement, self.manifest, scan, scan_dir)
        )

    def _elevate(self) -> bool:
        """Cache sudo credentials by suspending the app and running ``sudo -v``."""
        self.notify("This scan needs root — authenticating with sudo…")
        with self.app.suspend():
            result = subprocess.run(["sudo", "-v"], check=False)  # noqa: S603,S607
        if result.returncode != 0:
            self.notify("sudo authentication failed; scan cancelled.", severity="error")
            return False
        return True
