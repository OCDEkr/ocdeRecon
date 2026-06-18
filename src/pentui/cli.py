"""Command-line entry point.

Default (no subcommand) launches the Textual TUI. The ``run-workflow`` subcommand
runs a workflow **headless** — no TUI — against an existing engagement, so
workflows can be driven from cron/systemd/CI or any non-interactive context. It
reuses the same engine the TUI drives (scope guardrail, concurrency bound, parse
→ persist), printing step events to stdout and exiting non-zero if any step
errors.
"""

from __future__ import annotations

import argparse
import sys

from pentui import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pentui",
        description="TUI for wrapping and automating offensive-security tools.",
    )
    parser.add_argument("--version", action="version", version=f"pentui {__version__}")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser(
        "run-workflow",
        help="run a workflow headless (no TUI) against an existing engagement",
    )
    run.add_argument("engagement", help="engagement name (must already exist)")
    run.add_argument("workflow", help="workflow name (packaged or user)")
    run.add_argument(
        "--unattended",
        action="store_true",
        help="bypass approval gates (out-of-scope targets are still skipped)",
    )
    run.set_defaults(func=_run_workflow_command)
    return parser


def _run_workflow_command(args: argparse.Namespace) -> int:
    """Run one workflow headless; return 0 if every step succeeded, else 1."""
    import asyncio
    import os

    from pentui.config import AppConfig
    from pentui.core.registry import build_registry
    from pentui.core.workflow import (
        StepState,
        WorkflowEngine,
        WorkflowEvent,
        WorkflowStep,
        build_workflow_registry,
    )
    from pentui.persistence.db import EncryptionError
    from pentui.persistence.engagement import is_encrypted, open_engagement
    from pentui.persistence.repositories import ScopeRuleRepository

    config = AppConfig()
    config.ensure_dirs()

    workflows = build_workflow_registry(config.user_workflows_dir)
    workflow = workflows.get(args.workflow)
    if workflow is None:
        available = ", ".join(workflows.names()) or "(none)"
        print(f"unknown workflow {args.workflow!r}; available: {available}", file=sys.stderr)
        return 2

    if not config.engagement_db_path(args.engagement).exists():
        base = config.engagements_dir
        existing = (
            sorted(d.name for d in base.iterdir() if (d / "engagement.db").exists())
            if base.exists()
            else []
        )
        listed = ", ".join(existing) or "(none)"
        print(f"engagement {args.engagement!r} not found; existing: {listed}", file=sys.stderr)
        return 2

    passphrase = os.environ.get("PENTUI_DB_PASSPHRASE")
    if is_encrypted(config, args.engagement) and not passphrase:
        print(
            f"engagement {args.engagement!r} is encrypted; "
            "set PENTUI_DB_PASSPHRASE to run it headless",
            file=sys.stderr,
        )
        return 2
    try:
        engagement = open_engagement(config, args.engagement, passphrase=passphrase)
    except EncryptionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    registry = build_registry(config.user_tools_dir)
    rules = ScopeRuleRepository(engagement.conn).list_for_project(engagement.project_id)

    # Root is per-command in the engine; running the whole CLI as root skips
    # per-command sudo. Otherwise feed a password from the environment (so it
    # works under cron without a TTY); absent that, root-requiring steps fail
    # cleanly rather than hang on a prompt.
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    sudo_password = os.environ.get("PENTUI_SUDO_PASSWORD")

    def on_event(event: WorkflowEvent) -> None:
        print(f"[{event.step_id}] {event.detail}", flush=True)

    async def deny_gate(step: WorkflowStep) -> bool:
        # No TTY to approve in a headless run: skip gated steps and say so. Pass
        # --unattended to bypass gates intentionally.
        print(
            f"[{step.id}] gated step skipped (run with --unattended to bypass gates)",
            file=sys.stderr,
        )
        return False

    engine = WorkflowEngine(
        engagement,
        registry,
        config,
        scope_rules=rules,
        unattended=args.unattended,
        is_root=is_root,
        sudo_password=sudo_password,
        event_sink=on_event,
        gate_approver=None if args.unattended else deny_gate,
    )
    print(f"running workflow {workflow.name!r} on engagement {args.engagement!r}", flush=True)
    asyncio.run(engine.run(workflow))

    errored = sorted(s for s, st in engine.states.items() if st is StepState.ERROR)
    skipped = sorted(s for s, st in engine.states.items() if st is StepState.SKIPPED)
    done = sorted(s for s, st in engine.states.items() if st is StepState.DONE)
    print(f"done: {len(done)} ok, {len(errored)} errored, {len(skipped)} skipped", flush=True)
    if errored:
        print(f"errored steps: {', '.join(errored)}", file=sys.stderr)
    return 1 if errored else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) is not None:
        func = args.func
        assert callable(func)
        return int(func(args))
    # Imported lazily so `pentui --version` / `run-workflow` work without a
    # TTY/Textual setup.
    from pentui.app import PentuiApp

    PentuiApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
