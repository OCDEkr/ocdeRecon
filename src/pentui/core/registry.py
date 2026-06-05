"""Discovery of tools (and, later, parsers/workflows) — PROJECT.md §3, §4.

Loads tool manifests from the packaged ``tools/`` directory and the user config
dir. Invalid manifests are skipped and recorded in ``errors`` rather than
aborting startup, so one bad file can't take the whole app down.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from pentui.core.manifest import ManifestError, ToolManifest, load_manifest

#: Packaged manifests ship at <repo>/tools alongside the src/ tree.
PACKAGED_TOOLS_DIR = Path(__file__).resolve().parents[3] / "tools"


def tool_available(manifest: ToolManifest) -> bool:
    """Whether the tool's binary is resolvable (on PATH or an executable path)."""
    return shutil.which(manifest.binary) is not None


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolManifest] = {}
        self.errors: list[str] = []

    def load_dir(self, directory: str | Path) -> None:
        """Load every ``*.yaml`` / ``*.yml`` manifest in a directory (if it exists)."""
        directory = Path(directory)
        if not directory.is_dir():
            return
        for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
            try:
                manifest = load_manifest(path)
            except ManifestError as exc:
                self.errors.append(str(exc))
                continue
            self._tools[manifest.name] = manifest  # later dirs override earlier

    def get(self, name: str) -> ToolManifest | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[ToolManifest]:
        return [self._tools[name] for name in self.names()]


def build_registry(*directories: str | Path) -> ToolRegistry:
    """Build a registry from the packaged dir plus any extra (e.g. user) dirs.

    Later directories override earlier ones on name collision.
    """
    registry = ToolRegistry()
    registry.load_dir(PACKAGED_TOOLS_DIR)
    for directory in directories:
        registry.load_dir(directory)
    return registry
