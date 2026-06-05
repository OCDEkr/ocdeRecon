"""Workflow definitions + the orchestration engine (PROJECT.md §7).

Phase 4 — the core purpose. A workflow is a branching DAG of steps; each step
names a tool (+ profile/options), declares which steps it runs ``after``, and
optionally queries upstream results (via ``pentui.core.query``) for its inputs.

The WorkflowEngine topologically schedules steps, applies gates (unless the run
is unattended), runs ready steps through the ScanManager/Executor in parallel,
and persists WorkflowRun/StepRun state for resumability.
"""

from __future__ import annotations

# TODO(phase-4): WorkflowDefinition / WorkflowStep schema, DAG validation (no
# cycles), and WorkflowEngine.run(workflow, *, unattended) with gate handling and
# per-step failure policy (stop-branch | continue).
