"""Application configuration and filesystem paths.

Follows the XDG Base Directory spec. Engagement data (the sensitive recon) lives
under the data dir; user-supplied tools/parsers/workflows under the config dir.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

APP_NAME = "pentui"


def _xdg_dir(env_var: str, default: Path) -> Path:
    value = os.environ.get(env_var)
    return Path(value) if value else default


def data_home() -> Path:
    """Base directory for engagement databases and scan artifacts."""
    return _xdg_dir("XDG_DATA_HOME", Path.home() / ".local" / "share") / APP_NAME


def config_home() -> Path:
    """Base directory for user-supplied manifests/parsers/workflows."""
    return _xdg_dir("XDG_CONFIG_HOME", Path.home() / ".config") / APP_NAME


@dataclass(slots=True)
class AppConfig:
    """Runtime configuration for a pentui session."""

    data_dir: Path = field(default_factory=data_home)
    config_dir: Path = field(default_factory=config_home)
    #: Maximum number of scans/workflow steps running concurrently.
    max_concurrent_scans: int = 4

    @property
    def engagements_dir(self) -> Path:
        return self.data_dir / "engagements"

    @property
    def user_tools_dir(self) -> Path:
        return self.config_dir / "tools"

    @property
    def user_parsers_dir(self) -> Path:
        return self.config_dir / "parsers"

    @property
    def user_workflows_dir(self) -> Path:
        return self.config_dir / "workflows"

    def engagement_dir(self, name: str) -> Path:
        """Directory holding a single engagement's DB and scan artifacts."""
        return self.engagements_dir / name

    def engagement_db_path(self, name: str) -> Path:
        return self.engagement_dir(name) / "engagement.db"

    def scan_dir(self, engagement: str, scan_id: int) -> Path:
        """Where a scan's raw stdout log and artifacts (e.g. nmap.xml) are written."""
        return self.engagement_dir(engagement) / "scans" / str(scan_id)

    def reports_dir(self, engagement: str) -> Path:
        """Where exported reports are written for an engagement."""
        return self.engagement_dir(engagement) / "reports"

    def workflow_artifacts_dir(self, engagement: str, run_id: int, step_id: str) -> Path:
        """Where a workflow step's collected artifacts (e.g. per-/24 nmap XML) go."""
        return self.engagement_dir(engagement) / "artifacts" / str(run_id) / step_id

    def ensure_dirs(self) -> None:
        """Create the base data/config directories if missing."""
        for path in (self.engagements_dir, self.user_tools_dir,
                     self.user_parsers_dir, self.user_workflows_dir):
            path.mkdir(parents=True, exist_ok=True)

    @property
    def settings_file(self) -> Path:
        return self.config_dir / "settings.json"

    def load_settings(self) -> dict[str, Any]:
        try:
            data = json.loads(self.settings_file.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def save_settings(self, settings: dict[str, Any]) -> None:
        self.settings_file.parent.mkdir(parents=True, exist_ok=True)
        self.settings_file.write_text(json.dumps(settings, indent=2))
