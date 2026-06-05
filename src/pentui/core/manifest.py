"""Tool manifest schema + loader (PROJECT.md §5).

Phase 1. Manifests are declarative YAML describing how to build a tool's command,
which options need root, the offered profiles, and which parser handles output.
They are validated with Pydantic on load; invalid manifests are skipped with a
clear error rather than crashing the app.
"""

from __future__ import annotations

# TODO(phase-1): define ToolManifest, ToolOption, ToolProfile, OutputSpec, TargetSpec
# and a load_manifest(path) / load_manifests(dirs) loader.
