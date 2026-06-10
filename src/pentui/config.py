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


@dataclass(slots=True)
class NessusSettings:
    """Connection details for a local Nessus instance (REST API)."""

    url: str
    access_key: str | None
    secret_key: str | None

    @property
    def configured(self) -> bool:
        return bool(self.access_key and self.secret_key)


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

    def tool_output_root(self, engagement: str, tool: str | None = None) -> Path:
        """Base dir for a tool's scans in an engagement (each scan is a numbered
        subdir below this): ``<root>/<engagement>/scans/<tool>``.

        ``<root>`` is the configurable output root (see ``output_root``) — e.g.
        ``~/pentests`` — or the XDG engagements dir when unset. The engagement
        and per-tool segments are always present, so the same tool lands in
        different paths per engagement and each tool keeps its own folder. This
        is registry-driven: any tool name works with no per-tool code.
        """
        root = self.output_root()
        base = (root / engagement) if root else self.engagement_dir(engagement)
        scans = base / "scans"
        return scans / tool if tool else scans

    def scan_dir(self, engagement: str, scan_id: int, tool: str | None = None) -> Path:
        """Where a scan's raw stdout log and artifacts (e.g. nmap.xml) are written."""
        return self.tool_output_root(engagement, tool) / str(scan_id)

    def reports_dir(self, engagement: str) -> Path:
        """Where exported reports are written for an engagement."""
        return self.engagement_dir(engagement) / "reports"

    def workflow_artifacts_dir(self, engagement: str, run_id: int, step_id: str) -> Path:
        """Where a workflow step's collected artifacts (e.g. per-/24 nmap XML) go."""
        return self.engagement_dir(engagement) / "artifacts" / str(run_id) / step_id

    def ensure_dirs(self) -> None:
        """Create the base data/config directories if missing."""
        for path in (
            self.engagements_dir,
            self.user_tools_dir,
            self.user_parsers_dir,
            self.user_workflows_dir,
        ):
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

    def nessus_settings(self) -> NessusSettings:
        """Local Nessus connection details for the REST runner.

        Read from ``settings.json`` under the ``nessus`` key, with environment
        overrides (``NESSUS_URL`` / ``NESSUS_ACCESS_KEY`` / ``NESSUS_SECRET_KEY``)
        taking precedence. Keys live outside the repo and are never committed.
        Defaults to the standard local endpoint ``https://localhost:8834``.
        """
        raw = self.load_settings().get("nessus")
        stored = raw if isinstance(raw, dict) else {}
        url = os.environ.get("NESSUS_URL") or stored.get("url") or "https://localhost:8834"
        access = os.environ.get("NESSUS_ACCESS_KEY") or stored.get("access_key") or None
        secret = os.environ.get("NESSUS_SECRET_KEY") or stored.get("secret_key") or None
        return NessusSettings(url=str(url), access_key=access, secret_key=secret)

    def set_nessus_settings(
        self,
        *,
        url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
    ) -> None:
        """Persist Nessus connection details (only the provided fields)."""
        settings = self.load_settings()
        raw = settings.get("nessus")
        nessus: dict[str, Any] = raw if isinstance(raw, dict) else {}
        if url is not None:
            nessus["url"] = url
        if access_key is not None:
            nessus["access_key"] = access_key
        if secret_key is not None:
            nessus["secret_key"] = secret_key
        settings["nessus"] = nessus
        self.save_settings(settings)

    def output_root(self) -> Path | None:
        """Configurable base dir for scan output (the "pentests" folder), under
        which each engagement gets ``<engagement>/scans/<tool>/<scan_id>``.
        ``None`` (the default) keeps scans under the XDG engagements dir."""
        raw = self.load_settings().get("output_root")
        return Path(raw).expanduser() if isinstance(raw, str) and raw.strip() else None

    def set_output_root(self, directory: str | None) -> None:
        """Set (or clear, when ``directory`` is falsy) the scan-output root."""
        settings = self.load_settings()
        if directory and directory.strip():
            settings["output_root"] = directory.strip()
        else:
            settings.pop("output_root", None)
        self.save_settings(settings)

    def theme_mode(self) -> str:
        """``"dark"`` (default) or ``"light"`` — the UI brightness mode."""
        value = self.load_settings().get("theme_mode")
        return value if value in ("dark", "light") else "dark"

    def set_theme_mode(self, mode: str) -> None:
        settings = self.load_settings()
        settings["theme_mode"] = "light" if mode == "light" else "dark"
        self.save_settings(settings)

    def palette(self) -> str:
        """``"standard"`` (default) or ``"cb"`` — the colour-blind-safe accent axis."""
        value = self.load_settings().get("palette")
        return value if value in ("standard", "cb") else "standard"

    def set_palette(self, palette: str) -> None:
        settings = self.load_settings()
        settings["palette"] = "cb" if palette == "cb" else "standard"
        self.save_settings(settings)
