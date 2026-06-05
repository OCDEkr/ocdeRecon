"""Discovery of tools, parsers, and workflows (PROJECT.md §3, §4).

Phase 1+. Loads tool manifests from the packaged ``tools/`` dir and the user
config dir, registers parser plugins by name, and loads workflow definitions.
"""

from __future__ import annotations

# TODO(phase-1): Registry that scans packaged + user dirs for manifests/parsers/
# workflows, validates them, and exposes lookup by name.
