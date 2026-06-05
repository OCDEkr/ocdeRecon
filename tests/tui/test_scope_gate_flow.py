"""TUI test: out-of-scope targets are blocked, with a logged override path."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Input

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.persistence.repositories import AuditLogRepository, ScanRepository
from pentui.tui.screens.modals import ScopeBlockModal

from ._helpers import start_engagement


def _make_config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    (config.user_tools_dir / "echo.yaml").write_text(
        "name: echo\nbinary: echo\ntarget: {mode: append}\n"
    )
    return config


async def test_out_of_scope_cancel_blocks_scan(tmp_path):
    app = PentuiApp(config=_make_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="scoped", includes="10.0.0.0/24")
        app.screen.query_one("#targets", Input).value = "8.8.8.8"
        await pilot.pause()
        await pilot.click("#run")
        await pilot.pause()

        assert isinstance(app.screen, ScopeBlockModal)
        await pilot.click("#cancel")
        await pilot.pause()

        eng = app.engagement
        assert ScanRepository(eng.conn).list_recent(eng.project_id) == []


async def test_out_of_scope_override_runs_and_audits(tmp_path):
    app = PentuiApp(config=_make_config(tmp_path))
    async with app.run_test(size=(100, 50)) as pilot:
        await start_engagement(pilot, name="scoped", includes="10.0.0.0/24")
        app.screen.query_one("#targets", Input).value = "8.8.8.8"
        await pilot.pause()
        await pilot.click("#run")
        await pilot.pause()

        assert isinstance(app.screen, ScopeBlockModal)
        await pilot.click("#override")
        await app.workers.wait_for_complete()
        await pilot.pause()

        eng = app.engagement
        scans = ScanRepository(eng.conn).list_recent(eng.project_id)
        assert len(scans) == 1
        actions = [a for _, a, _ in AuditLogRepository(eng.conn).list_for_project(eng.project_id)]
        assert "scope_override" in actions
