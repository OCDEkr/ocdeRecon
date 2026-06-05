"""Data-handoff query layer (PROJECT.md §7.2).

Phase 4. A small, SAFE, non-arbitrary selector over the unified model that lets a
workflow step pick its inputs from upstream results (no raw SQL, no eval).

Initial ``where`` conditions: port_open_in, service_name_in, state,
has_finding_severity, hostname_matches (combinable with and/or).
Initial ``as`` materializers: targets (IPs/hostnames), target_urls
(host+port -> http(s) URL), ip_list/file (for manifest target.mode: flag).
"""

from __future__ import annotations

# TODO(phase-4): Query schema (from/where/as), evaluate(project_id) -> selected
# entities, and materializers that turn selections into a downstream tool's input.
