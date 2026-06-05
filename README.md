# pentui

A terminal user interface (TUI) that wraps and **automates** command-line
offensive-security tools, built for a cybersecurity department running authorized
penetration tests. Its purpose is to reduce manual input by chaining tools into
workflows — one tool's output automatically feeds the next.

**Nmap is the proof of concept.** The architecture treats every tool as a
pluggable manifest, and every multi-tool process as a definable workflow.

> ⚠️ For **authorized** security testing only. Engagements define explicit scope;
> out-of-scope targets are never scanned.

See [`PROJECT.md`](./PROJECT.md) for the full specification and architecture.

## Status

Phase 2 — a tool can be configured from a YAML manifest, run from the TUI with
live output (sudo handled for root-only options), and its output parsed into the
unified Host→Port→Service model, persisted to a per-engagement SQLite database,
and browsed in a results screen. Scope enforcement (Phase 3) and workflow
orchestration (Phase 4) are not built yet. See `PROJECT.md` §16 for the roadmap.

## Quick start (development)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pentui                 # launch the TUI (placeholder in Phase 0)
pytest                 # run tests
ruff check . && mypy src
```
