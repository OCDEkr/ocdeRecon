"""Async subprocess execution (PROJECT.md §9).

Phase 1. Builds the command as an argv LIST (never a shell string, never
shell=True), scope-checks targets, decides on sudo elevation from manifest
``requires_root`` flags, streams stdout/stderr, and tees raw output to disk. On
exit it invokes the manifest's parser and hands the ScanResult back to core.
"""

from __future__ import annotations

# TODO(phase-1): build_argv(manifest, profile, options, targets) and an async
# run(scan) coroutine using asyncio.create_subprocess_exec with streaming.
