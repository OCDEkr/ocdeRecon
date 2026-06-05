"""Report generation from the engagement DB (PROJECT.md §12).

Phase 5. Markdown/HTML via Jinja2 templates (HTML self-contained), JSON full dump,
CSV findings/inventory. Reports include scope, date range, tools/commands run, and
the workflow + steps for automated runs (traceability for deliverables).
"""

from __future__ import annotations

# TODO(phase-5): export(project_id, fmt, out_path) for fmt in {markdown, html, json, csv}.
