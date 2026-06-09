"""Concurrency manager for running scans / workflow steps (PROJECT.md §9).

Phase 1. Tracks in-flight scans, enforces ``AppConfig.max_concurrent_scans``,
and queues the rest. Each scan is a cancellable async task.
"""

from __future__ import annotations

# TODO(phase-1): ScanManager.submit(scan) / cancel(scan_id) with a bounded
# concurrency pool (asyncio.Semaphore) and a queue for overflow.
