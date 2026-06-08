"""TUI test: batch a file-input tool over a directory (one run per file)."""

from __future__ import annotations

from pathlib import Path

from textual.widgets import Select, Static

from pentui.app import PentuiApp
from pentui.config import AppConfig
from pentui.core.models import ScanStatus
from pentui.persistence.repositories import ScanRepository

from ._helpers import start_engagement

# Prints the file passed to -f, so the aggregate log shows each batched file.
BATCH_TOOL = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "f = None\n"
    "for i, a in enumerate(sys.argv):\n"
    "    if a == '-f':\n"
    "        f = sys.argv[i + 1]\n"
    "print('shot', f)\n"
)


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    script = tmp_path / "batchshot"
    script.write_text(BATCH_TOOL)
    script.chmod(0o755)
    (config.user_tools_dir / "batchshot.yaml").write_text(
        f"name: batchshot\nbinary: {script}\ntarget: {{mode: append}}\n"
        f"options:\n"
        f"  - {{flag: '-f', label: Input, type: value, file_input: true, file_glob: '*.xml'}}\n"
    )
    return config


async def test_batch_runs_once_per_file(tmp_path):
    config = _config(tmp_path)
    xmls = config.data_dir / "nmaps"
    xmls.mkdir(parents=True)
    (xmls / "net-a.xml").write_text("a")
    (xmls / "net-b.xml").write_text("b")

    app = PentuiApp(config=config)
    async with app.run_test(size=(120, 50)) as pilot:
        await start_engagement(pilot, name="batch", targets="")
        app.screen.query_one("#tool", Select).value = "batchshot"
        await pilot.pause()
        # Point the file-input option at the directory.
        for option, widget in app.screen._option_widgets:
            if option.flag == "-f":
                widget.value = str(xmls)
        await pilot.pause()
        await pilot.click("#run")
        await app.workers.wait_for_complete()
        await pilot.pause()

        status = str(app.screen.query_one("#status", Static).render())
        assert "2/2" in status

        eng = app.engagement
        scan = ScanRepository(eng.conn).list_recent(eng.project_id)[0]
        assert scan.status is ScanStatus.DONE
        log = (config.scan_dir("batch", scan.id) / "stdout.log").read_text()
        assert "net-a.xml" in log and "net-b.xml" in log
