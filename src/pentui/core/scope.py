"""Scope enforcement (PROJECT.md §10).

Phase 3. Evaluates targets against a project's include/exclude rules using the
stdlib ``ipaddress`` module. Manual out-of-scope runs are blocked with a logged
override path; workflow steps skip-and-log out-of-scope targets and never scan
them, even when a run is unattended.
"""

from __future__ import annotations

# TODO(phase-3): ScopeChecker(rules).classify(target) -> in_scope | out_of_scope,
# plus expansion of CIDRs and audit logging of overrides/skips.
