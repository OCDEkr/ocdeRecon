"""Command-line entry point.

Default (no subcommand) launches the Textual TUI. The ``run-workflow`` subcommand
runs a workflow **headless** — no TUI — against an existing engagement, so
workflows can be driven from cron/systemd/CI or any non-interactive context. It
reuses the same engine the TUI drives (scope guardrail, concurrency bound, parse
→ persist), printing step events to stdout and exiting non-zero if any step
errors.

The ``configure`` subcommand provisions the **global** settings that live in
``~/.config/pentui/settings.json`` — Nessus connection/keys, the scan-output
root, theme mode and palette. Because Nessus keys are global (not per-engagement)
and an engagement can auto-launch the ``engagement-recon`` workflow — whose
``vuln-scan`` step needs those keys — on the very first run, ``configure`` lets an
operator set them up front (e.g. from ``deploy.sh --configure``) before any
engagement exists. It runs an interactive wizard on a TTY, or applies any of the
``--nessus-*``/``--output-root``/``--theme``/``--palette`` flags non-interactively.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING

from pentui import __version__

if TYPE_CHECKING:
    from pentui.config import AppConfig


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

    cfg = sub.add_parser(
        "configure",
        help="set global settings (Nessus keys, output root, theme) — interactive or via flags",
    )
    cfg.add_argument("--nessus-url", metavar="URL", help="Nessus REST base URL")
    cfg.add_argument("--nessus-access-key", metavar="KEY", help="Nessus API access key")
    cfg.add_argument("--nessus-secret-key", metavar="KEY", help="Nessus API secret key")
    cfg.add_argument(
        "--output-root",
        metavar="DIR",
        help="scan-output root (the 'pentests' folder); pass '' to clear",
    )
    cfg.add_argument("--theme", choices=["dark", "light"], help="UI brightness mode")
    cfg.add_argument(
        "--palette", choices=["standard", "cb"], help="accent palette (cb = colour-blind-safe)"
    )
    cfg.set_defaults(func=_configure_command)
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


def _mask(value: str | None) -> str:
    """Render a stored key for a prompt without echoing it in full."""
    if not value:
        return "not set"
    return "••••" + value[-4:] if len(value) > 4 else "set"


def _apply_settings(
    config: AppConfig,
    *,
    nessus_url: str | None = None,
    nessus_access_key: str | None = None,
    nessus_secret_key: str | None = None,
    output_root: str | None = None,
    theme: str | None = None,
    palette: str | None = None,
) -> None:
    """Persist the provided settings via the config setters (safe JSON merge).

    ``None`` means "leave unchanged". For Nessus keys an empty string is treated
    as ``None`` (keep the stored value) since a blank prompt means "no change";
    ``output_root`` is the exception — an empty string clears it.
    """
    nu = nessus_url or None
    na = nessus_access_key or None
    ns = nessus_secret_key or None
    if nu is not None or na is not None or ns is not None:
        config.set_nessus_settings(url=nu, access_key=na, secret_key=ns)
    if output_root is not None:
        config.set_output_root(output_root)
    if theme is not None:
        config.set_theme_mode(theme)
    if palette is not None:
        config.set_palette(palette)


def _interactive_configure(config: AppConfig) -> int:
    """Prompt for each global setting; blank input keeps the current value."""
    import getpass

    nessus = config.nessus_settings()
    print("pentui configuration — leave a field blank to keep its current value.\n")
    print("Nessus (local REST API):")
    url = input(f"  URL [{nessus.url}]: ").strip()
    access = input(f"  Access key [{_mask(nessus.access_key)}]: ").strip()
    secret = getpass.getpass(f"  Secret key [{_mask(nessus.secret_key)}]: ").strip()

    current_root = config.output_root()
    root = input(f"\nScan output root [{current_root or 'default (XDG data dir)'}]: ").strip()

    theme = input(f"\nTheme mode (dark/light) [{config.theme_mode()}]: ").strip().lower()
    palette = input(f"Palette (standard/cb) [{config.palette()}]: ").strip().lower()

    _apply_settings(
        config,
        nessus_url=url,
        nessus_access_key=access,
        nessus_secret_key=secret,
        output_root=root or None,
        theme=theme if theme in ("dark", "light") else None,
        palette=palette if palette in ("standard", "cb") else None,
    )
    print(f"\nsaved to {config.settings_file}")
    return 0


def _configure_command(args: argparse.Namespace) -> int:
    """Set global settings — non-interactive when any flag is given, else a wizard."""
    from pentui.config import AppConfig

    config = AppConfig()
    config.ensure_dirs()

    flags = (
        args.nessus_url,
        args.nessus_access_key,
        args.nessus_secret_key,
        args.output_root,
        args.theme,
        args.palette,
    )
    if any(v is not None for v in flags):
        _apply_settings(
            config,
            nessus_url=args.nessus_url,
            nessus_access_key=args.nessus_access_key,
            nessus_secret_key=args.nessus_secret_key,
            output_root=args.output_root,
            theme=args.theme,
            palette=args.palette,
        )
        print(f"settings updated: {config.settings_file}")
        return 0

    if not sys.stdin.isatty():
        print(
            "pentui configure: no settings flags given and stdin is not a TTY; "
            "pass --nessus-url/--nessus-access-key/... or run it in a terminal",
            file=sys.stderr,
        )
        return 2
    return _interactive_configure(config)


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
