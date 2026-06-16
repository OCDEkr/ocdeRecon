"""Tool configuration screen (PROJECT.md §11).

Phase 1: pick a tool + profile, toggle manifest-defined options, enter targets,
and see a live command preview. Launching hands off to the scan monitor. Root
elevation is confirmed here (the app suspends so ``sudo`` can prompt on the real
terminal) — core stays UI-free.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import TYPE_CHECKING, cast

from textual import on, work
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

from pentui.config import AppConfig, target_slug
from pentui.core.executor import (
    ExecutorError,
    build_argv,
    build_runs,
    config_tokens,
    file_input_batch,
    preview,
    requires_root,
)
from pentui.core.manifest import (
    OptionType,
    ToolKind,
    ToolManifest,
    ToolOption,
    ToolProfile,
    save_manifest,
)
from pentui.core.models import Scan, ScopeKind
from pentui.core.registry import ToolRegistry, tool_available
from pentui.core.scope import ScopeStatus, classify_targets, write_exclude_file
from pentui.persistence.engagement import Engagement
from pentui.persistence.repositories import (
    AuditLogRepository,
    ScanRepository,
    ScopeRuleRepository,
    TargetRepository,
)
from pentui.tui.screens.modals import ScopeBlockModal, TextPromptModal

if TYPE_CHECKING:
    from pentui.app import PentuiApp

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

    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("ctrl+r", "run", "Run scan"),
        ("ctrl+t", "use_targets", "Use project targets"),
        ("q", "app.quit", "Quit"),
    ]

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
        # REST tools (e.g. Nessus) run via workflows, not ad-hoc manual scans, so
        # they're excluded from this screen's tool list.
        self._manual_tools = [m for m in registry.all() if m.kind is not ToolKind.REST]
        self.manifest: ToolManifest | None = self._manual_tools[0] if self._manual_tools else None
        self._option_widgets: list[tuple[ToolOption, Checkbox | Input | Select[str]]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        if self.manifest is None:
            yield Static(
                "No tool manifests found. Add one under tools/ or ~/.config/pentui/tools/.",
                id="cmd",
            )
            yield Footer()
            return
        tool_opts = [(m.name, m.name) for m in self._manual_tools]
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
        yield Static("↑/↓ move between fields", classes="hint")
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
        yield Horizontal(
            Label("Extra args:"),
            Input(placeholder="any flags, e.g. --top-ports 100", id="extra-args"),
            classes="field",
        )
        yield Static("", id="cmd")
        yield Horizontal(
            Button("Run scan", variant="primary", id="run"),
            Button("Use project targets", id="load_targets"),
            Button("Save as profile", id="save-profile"),
            id="controls",
        )
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
        # value option — pre-fill its default (e.g. --threads 16) so it's applied
        # unless the operator clears it.
        return Input(value=option.default or "", placeholder=option.placeholder or "")

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

    def _extra_args(self) -> list[str]:
        try:
            return shlex.split(self.query_one("#extra-args", Input).value)
        except ValueError as exc:
            raise ExecutorError("unbalanced quotes in extra args") from exc

    def _exclude_args(self) -> list[str]:
        """``--excludefile <path>`` for tools that accept one, when the engagement
        has exclude rules. Read-only (deterministic path); the file is written at
        launch by ``_launch``. Shown in the preview so the operator sees it."""
        if self.manifest is None or not self.manifest.exclude_flag:
            return []
        rules = ScopeRuleRepository(self.engagement.conn).list_for_project(
            self.engagement.project_id
        )
        if not any(r.kind is ScopeKind.EXCLUDE for r in rules):
            return []
        path = self.config.engagement_exclude_file(self.engagement.name)
        return [self.manifest.exclude_flag, str(path)]

    def _try_build(self, *, sudo: bool, scan_dir: str | None) -> list[str]:
        assert self.manifest is not None
        return build_argv(
            self.manifest,
            profile=self._current_profile(),
            options=self._current_options(),
            extra_args=[*self._extra_args(), *self._exclude_args()],
            targets=self._current_targets(),
            scan_dir=scan_dir or "{scan_dir}",
            sudo=sudo,
        )

    def _update_preview(self) -> None:
        try:
            argv = self._try_build(sudo=False, scan_dir=None)
        except ExecutorError as exc:
            self.query_one("#cmd", Static).update(f"[red]⚠ {exc}[/red]")
            return
        text = preview(argv)
        if self.manifest is not None:
            batch = file_input_batch(self.manifest, self._current_options())
            if batch is not None:
                text += f"\n[cyan]↻ batch: once per file in directory ({len(batch)} matched)[/cyan]"
            if not tool_available(self.manifest):
                text += f"\n[yellow]⚠ '{self.manifest.binary}' not found on PATH[/yellow]"
        self.query_one("#cmd", Static).update(text)

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
        # Run in a worker so the scope-override modal can use push_screen_wait.
        self._launch()

    def action_run(self) -> None:
        """Keyboard shortcut (Ctrl+R) for the Run scan button."""
        self._launch()

    def action_use_targets(self) -> None:
        """Keyboard shortcut (Ctrl+T) for the Use-project-targets button."""
        self._load_targets()

    @work
    async def _launch(self) -> None:
        if self.manifest is None:
            return
        try:
            self._try_build(sudo=False, scan_dir=None)  # validate options/extra args
        except ExecutorError as exc:
            self.notify(str(exc), severity="error", title="Invalid command")
            return

        options = self._current_options()
        targets = self._current_targets()
        # A file-input option pointed at a directory batches once per matching file.
        batch = file_input_batch(self.manifest, options)
        if batch is not None and not batch:
            self.notify("No matching files in that directory.", severity="warning")
            return

        if not await self._scope_gate(targets):
            return

        profile = self._current_profile()
        need_root = requires_root(self.manifest, profile=profile, options=options)
        use_sudo = need_root and os.geteuid() != 0
        sudo_password = None
        if use_sudo:
            sudo_password = await cast("PentuiApp", self.app).request_sudo_password()
            if sudo_password is None:
                self.notify("Root password required — scan cancelled.", severity="warning")
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
        name = target_slug(targets)
        scan_dir = str(
            self.config.scan_dir(
                self.engagement.name,
                scan.id,
                tool=self.manifest.name,
                leaf=name,
                output_root_override=self.engagement.output_root_override,
            )
        )
        # Materialize the engagement-wide exclude file so a tool that supports
        # --excludefile honors out-of-scope ranges (see _exclude_args for the flag).
        if self.manifest.exclude_flag:
            write_exclude_file(
                ScopeRuleRepository(self.engagement.conn).list_for_project(
                    self.engagement.project_id
                ),
                self.config.engagement_exclude_file(self.engagement.name),
            )
        runs = build_runs(
            self.manifest,
            profile=profile,
            options=options,
            extra_args=[*self._extra_args(), *self._exclude_args()],
            targets=targets,
            scan_dir=scan_dir,
            sudo=use_sudo,
        )
        note = f"   (+{len(runs) - 1} more files)" if len(runs) > 1 else ""
        scan.command_str = preview(runs[0][1]) + note
        scan.args = runs[0][1]
        if self.manifest.output.artifact is not None:
            scan.artifact_path = self.manifest.output.artifact.path.format(
                scan_dir=scan_dir, name=name or "scan"
            )
        scans.update(scan)
        if use_sudo:
            self._audit("sudo_run", scan.command_str)

        from pentui.tui.screens.scan_monitor import ScanMonitorScreen

        self.app.push_screen(
            ScanMonitorScreen(
                self.engagement,
                self.manifest,
                scan,
                scan_dir,
                runs,
                sudo_password=sudo_password,
            )
        )

    @on(Button.Pressed, "#load_targets")
    def _load_targets(self) -> None:
        saved = TargetRepository(self.engagement.conn).list_for_project(self.engagement.project_id)
        if not saved:
            self.notify("No saved targets for this engagement.", severity="warning")
            return
        self.query_one("#targets", Input).value = " ".join(t.value for t in saved)

    @on(Button.Pressed, "#save-profile")
    def _on_save_profile(self) -> None:
        if self.manifest is None:
            return
        try:
            tokens = config_tokens(
                self.manifest,
                profile=self._current_profile(),
                options=self._current_options(),
                extra_args=self._extra_args(),
            )
        except ExecutorError as exc:
            self.notify(str(exc), severity="error")
            return
        if not tokens:
            self.notify("Set a profile, options, or extra args first.", severity="warning")
            return
        manifest = self.manifest

        def on_name(name: str | None) -> None:
            if name:
                self._write_profile(manifest, name, tokens)

        self.app.push_screen(
            TextPromptModal(f"Save current {manifest.name} config as profile:", "profile name"),
            on_name,
        )

    def _write_profile(self, manifest: ToolManifest, name: str, tokens: list[str]) -> None:
        # Write a full user-manifest override merging the new profile in.
        profiles = [p for p in manifest.profiles if p.name != name]
        profiles.append(ToolProfile(name=name, args=tokens))
        updated = manifest.model_copy(update={"profiles": profiles})
        save_manifest(updated, self.config.user_tools_dir / f"{manifest.name}.yaml")
        self.registry.reload(self.config.user_tools_dir)
        self.manifest = self.registry.get(manifest.name)
        self.query_one("#profile", Select).set_options(self._profile_options())
        self.notify(f"Saved profile '{name}' for {manifest.name}.")

    async def _scope_gate(self, targets: list[str]) -> bool:
        """Enforce engagement scope. Returns True if the run may proceed.

        Out-of-scope targets block the run; the operator may override, which is
        recorded in the audit log. With no scope rules defined we warn and allow.
        """
        rules = ScopeRuleRepository(self.engagement.conn).list_for_project(
            self.engagement.project_id
        )
        decisions = classify_targets(rules, targets)
        if decisions and decisions[0].status is ScopeStatus.NO_RULES:
            self.notify(
                "No scope defined for this engagement — scanning without a guardrail.",
                severity="warning",
            )
            return True
        blocked = [d.target for d in decisions if d.blocked]
        if not blocked:
            return True
        overridden = await self.app.push_screen_wait(ScopeBlockModal(blocked))
        if not overridden:
            self.notify("Out-of-scope targets — scan cancelled.", severity="warning")
            return False
        self._audit("scope_override", "scanned out of scope: " + ", ".join(blocked))
        return True

    def _audit(self, action: str, detail: str) -> None:
        AuditLogRepository(self.engagement.conn).log(self.engagement.project_id, action, detail)
