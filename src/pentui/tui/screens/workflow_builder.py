"""Interactive workflow builder (PROJECT.md §2, §7, §11).

Chain tools without writing YAML: add steps (tool + profile), choose what each
step feeds on (the project target list or a query of a prior step's results),
mark approval gates, then save the workflow (and optionally run it). Saved
workflows are plain YAML under the user workflows dir and appear on the launch
screen alongside the packaged ones.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)

from pentui.config import AppConfig
from pentui.core.executor import ExecutorError, build_argv, preview, requires_root
from pentui.core.query import Materializer, QuerySpec, WhereSpec
from pentui.core.registry import ToolRegistry, tool_available
from pentui.core.workflow import (
    FileFrom,
    StepTargets,
    WorkflowDefinition,
    WorkflowError,
    WorkflowStep,
    save_workflow,
)
from pentui.persistence.engagement import Engagement

_NAME = re.compile(r"^[A-Za-z0-9_-]+$")

#: Feed presets → how a step gets its targets. Query feeds need an upstream step.
_FEEDS: dict[str, tuple[str, bool]] = {
    # id: (label, needs_upstream)
    "project": ("Project target list", False),
    "none": ("No input", False),
    "web": ("Web URLs from prior (80/443/8080/8443)", True),
    "smb": ("SMB hosts from prior (445)", True),
    "live": ("Live hosts from prior", True),
    "files": ("Files from prior step (-f, batched)", True),
}


def _feed_options() -> list[tuple[str, str]]:
    return [(label, key) for key, (label, _) in _FEEDS.items()]


class WorkflowBuilderScreen(Screen[None]):
    """Assemble a workflow step by step and save/run it."""

    DEFAULT_CSS = """
    WorkflowBuilderScreen { layout: vertical; }
    #meta, #addrow, #addrow2, #addrow3, #controls { height: auto; padding: 0 1; }
    #step-cmd { color: $text-muted; padding: 0 1; }
    #steps { height: 1fr; min-height: 5; border: round $panel; margin: 0 1; }
    Label { padding: 1 1 0 0; }
    Button { margin: 1 1 0 0; }
    Select, Input { width: 1fr; }
    """

    BINDINGS = [("escape", "app.pop_screen", "Back"), ("q", "app.quit", "Quit")]

    def __init__(
        self, engagement: Engagement, registry: ToolRegistry, config: AppConfig
    ) -> None:
        super().__init__()
        self.engagement = engagement
        self.registry = registry
        self.config = config
        self.steps: list[WorkflowStep] = []

    def compose(self) -> ComposeResult:
        tools = self.registry.names()
        yield Header()
        yield Horizontal(
            Label("Name:"),
            Input(placeholder="workflow-name", id="wf-name"),
            Label("Description:"),
            Input(placeholder="optional", id="wf-desc"),
            id="meta",
        )
        yield Horizontal(
            Label("Tool:"),
            Select([(t, t) for t in tools], value=tools[0] if tools else Select.BLANK,
                   allow_blank=not tools, id="step-tool"),
            Label("Profile:"),
            Select(self._profile_options(tools[0] if tools else None),
                   allow_blank=True, id="step-profile"),
            id="addrow",
        )
        yield Horizontal(
            Label("Extra args:"),
            Input(placeholder="any flags, e.g. -sV --top-ports 100", id="step-args"),
            id="addrow3",
        )
        yield Static("", id="step-cmd")
        yield Horizontal(
            Label("After:"),
            Select([], allow_blank=True, id="step-after"),
            Label("Feed:"),
            Select(_feed_options(), value="project", allow_blank=False, id="step-feed"),
            Checkbox("Per /24", id="step-foreach"),
            Checkbox("Gate", id="step-gate"),
            Button("Add step", id="add-step"),
            id="addrow2",
        )
        yield DataTable(id="steps")
        yield Horizontal(
            Button("Save", variant="primary", id="save"),
            Button("Save & run", variant="success", id="save-run"),
            Button("Remove last", id="remove"),
            id="controls",
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#steps", DataTable)
        table.add_columns("Step", "Tool", "Profile", "Args", "After", "Feed", "Gate")
        self._update_preview()

    # -- helpers ----------------------------------------------------------- #
    def _profile_options(self, tool: str | None) -> list[tuple[str, str]]:
        manifest = self.registry.get(tool) if tool else None
        return [(p.name, p.name) for p in manifest.profiles] if manifest else []

    @on(Select.Changed, "#step-tool")
    def _on_tool_changed(self, event: Select.Changed) -> None:
        tool = event.value if isinstance(event.value, str) else None
        self.query_one("#step-profile", Select).set_options(self._profile_options(tool))
        self._update_preview()

    @on(Select.Changed, "#step-profile")
    @on(Input.Changed, "#step-args")
    def _on_command_changed(self) -> None:
        self._update_preview()

    def _parsed_extra_args(self) -> list[str] | None:
        """shlex-split the extra-args field; None if quotes are unbalanced."""
        try:
            return shlex.split(self.query_one("#step-args", Input).value)
        except ValueError:
            return None

    def _update_preview(self) -> None:
        cmd = self.query_one("#step-cmd", Static)
        tool = self.query_one("#step-tool", Select).value
        manifest = self.registry.get(tool) if isinstance(tool, str) else None
        if manifest is None:
            cmd.update("")
            return
        extra = self._parsed_extra_args()
        if extra is None:
            cmd.update("[red]⚠ unbalanced quotes in extra args[/red]")
            return
        profile_val = self.query_one("#step-profile", Select).value
        profile = manifest.profile(profile_val) if isinstance(profile_val, str) else None
        try:
            # targets are supplied at run time from the feed; show a placeholder.
            argv = build_argv(manifest, profile=profile, extra_args=extra, scan_dir="{scan_dir}")
        except ExecutorError as exc:
            cmd.update(f"[red]⚠ {exc}[/red]")
            return
        note = "" if tool_available(manifest) else "  [yellow](binary not found)[/yellow]"
        cmd.update(f"$ {preview(argv)} <targets>{note}")

    def _unique_id(self, tool: str) -> str:
        existing = {s.id for s in self.steps}
        if tool not in existing:
            return tool
        i = 2
        while f"{tool}-{i}" in existing:
            i += 1
        return f"{tool}-{i}"

    @on(Button.Pressed, "#add-step")
    def _add_step(self) -> None:
        tool = self.query_one("#step-tool", Select).value
        if not isinstance(tool, str):
            self.notify("Pick a tool.", severity="warning")
            return
        profile_val = self.query_one("#step-profile", Select).value
        profile = profile_val if isinstance(profile_val, str) else None
        after_val = self.query_one("#step-after", Select).value
        after = [after_val] if isinstance(after_val, str) else []
        feed = self.query_one("#step-feed", Select).value
        _, needs_upstream = _FEEDS[str(feed)]
        if needs_upstream and not after:
            self.notify("That feed reads a prior step — set 'After' first.", severity="warning")
            return
        extra = self._parsed_extra_args()
        if extra is None:
            self.notify("Extra args have unbalanced quotes.", severity="error")
            return
        feed_kwargs = self._feed_kwargs(str(feed), after)
        foreach = None
        if self.query_one("#step-foreach", Checkbox).value:
            if "input" not in feed_kwargs:
                self.notify("Per-/24 needs a query feed (web/smb/live).", severity="warning")
                return
            foreach = "subnet/24"

        step = WorkflowStep(
            id=self._unique_id(tool),
            tool=tool,
            profile=profile,
            extra_args=extra,
            after=after,
            gate=self.query_one("#step-gate", Checkbox).value,
            foreach=foreach,
            **feed_kwargs,
        )
        self.steps.append(step)
        self._refresh_steps()
        # Make the new step selectable as an upstream for later steps.
        self.query_one("#step-after", Select).set_options(
            [(s.id, s.id) for s in self.steps]
        )

    def _feed_kwargs(self, feed: str, after: list[str]) -> dict[str, object]:
        if feed == "project":
            return {"targets": StepTargets(**{"from": "project"})}
        if feed == "web":
            return {"input": QuerySpec(where=WhereSpec(port_open_in=[80, 443, 8080, 8443]),
                                       **{"as": Materializer.TARGET_URLS})}
        if feed == "smb":
            return {"input": QuerySpec(where=WhereSpec(port_open_in=[445]))}
        if feed == "live":
            return {"input": QuerySpec(where=WhereSpec(host_state="up"))}
        if feed == "files":
            return {"file_from": FileFrom(step=after[0], flag="-f")}
        return {}  # "none"

    def _feed_label(self, step: WorkflowStep) -> str:
        if step.targets is not None:
            base = "project"
        elif step.input is not None:
            where = step.input.where.model_dump(exclude_none=True, exclude_defaults=True)
            base = f"{step.input.as_.value} ⊃ {where}"
        elif step.file_from is not None:
            base = f"files from {step.file_from.step} ({step.file_from.flag})"
        else:
            base = "—"
        return f"per-{step.foreach} · {base}" if step.foreach else base

    def _refresh_steps(self) -> None:
        table = self.query_one("#steps", DataTable)
        table.clear()
        for s in self.steps:
            table.add_row(
                s.id, s.tool, s.profile or "-", " ".join(s.extra_args) or "-",
                ", ".join(s.after) or "-", self._feed_label(s), "yes" if s.gate else "no",
            )

    @on(Button.Pressed, "#remove")
    def _remove_last(self) -> None:
        if self.steps:
            self.steps.pop()
            self._refresh_steps()
            self.query_one("#step-after", Select).set_options(
                [(s.id, s.id) for s in self.steps]
            )

    # -- save / run -------------------------------------------------------- #
    def _build_definition(self) -> WorkflowDefinition | None:
        name = self.query_one("#wf-name", Input).value.strip()
        if not _NAME.match(name):
            self.notify("Name must be letters, digits, - or _.", severity="error")
            return None
        if not self.steps:
            self.notify("Add at least one step.", severity="warning")
            return None
        desc = self.query_one("#wf-desc", Input).value.strip() or None
        try:
            return WorkflowDefinition(name=name, description=desc, steps=list(self.steps))
        except (WorkflowError, ValueError) as exc:
            self.notify(f"Invalid workflow: {exc}", severity="error")
            return None

    def _save(self) -> WorkflowDefinition | None:
        wf = self._build_definition()
        if wf is None:
            return None
        path = self.config.user_workflows_dir / f"{wf.name}.yaml"
        save_workflow(wf, path)
        self.notify(f"Saved workflow '{wf.name}'.")
        return wf

    @on(Button.Pressed, "#save")
    def _on_save(self) -> None:
        self._save()

    @on(Button.Pressed, "#save-run")
    def _on_save_run(self) -> None:
        wf = self._save()
        if wf is None:
            return
        is_root = os.geteuid() == 0
        if self._needs_root(wf) and not is_root and not self._elevate():
            return
        from pentui.tui.screens.workflow_monitor import WorkflowMonitorScreen

        self.app.push_screen(
            WorkflowMonitorScreen(
                self.engagement, self.registry, self.config, wf,
                unattended=False, is_root=is_root,
            )
        )

    def _needs_root(self, wf: WorkflowDefinition) -> bool:
        for step in wf.steps:
            manifest = self.registry.get(step.tool)
            if manifest is None:
                continue
            profile = manifest.profile(step.profile) if step.profile else None
            if requires_root(manifest, profile=profile, options=step.options):
                return True
        return False

    def _elevate(self) -> bool:
        self.notify("This workflow has root steps — authenticating with sudo…")
        with self.app.suspend():
            result = subprocess.run(["sudo", "-v"], check=False)  # noqa: S603,S607
        if result.returncode != 0:
            self.notify("sudo authentication failed.", severity="error")
            return False
        return True
