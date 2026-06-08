# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pentui` — a Textual-based TUI that wraps and **automates** command-line
offensive-security tools for authorized penetration testing. Its purpose is to
**chain tools into workflows** so one tool's output feeds the next without manual
intervention. **Nmap is the proof of concept.** All six build phases are
implemented: engagements with scope rules/targets; manifest-driven tool runs with
live output and scope guardrail; results parsed into the unified model, persisted,
and browsed; a **workflow engine** that chains tools as a DAG (query handoff,
approval gates, unattended mode); **report export** to Markdown/HTML/JSON/CSV; and
polish (blue/white + colour-blind-safe themes, tool-availability hints, audit-log
viewer). Workflows can be **built interactively in the TUI** (chain tools without
writing YAML) and saved as YAML, in addition to the packaged templates; each step
shows a live command preview and takes free-form extra args (not just profiles).
Every
screen that lists tools is driven by the registry, so adding a manifest makes the
tool available in manual scans, the builder, and workflows with no code change.
A configured scan (profile + options + extra args) can be **saved as a named
profile** from the scan screen — written as a user-manifest override under
`~/.config/pentui/tools/` (merged with the tool's existing profiles) and the
in-memory registry is reloaded so it shows up immediately.
A manifest option may set `file_input: true` (with `file_glob`); pointing it at a
directory **batches the run once per matching file** (e.g. gowitness `-f` over a
folder of nmap XMLs). A workflow step may `foreach: subnet/24` to **fan out into
one run per /24** of the hosts its `input` selects, and `file_from: {step, flag}`
to feed a downstream file-input flag the **collected artifacts** of an upstream
step (each run's artifact is copied into a per-step dir). The shipped
`subnet-recon` workflow chains masscan → per-/24 nmap → gowitness this way. Running scans/steps can be stopped with `s` (the process
group is terminated).
Shipped tool manifests: nmap, masscan, nslookup, gowitness, nxc, responder,
ntlmrelayx, mitm6, nessus. Deferred to future work (§14): parallel step execution,
SQLCipher-encrypted engagements, PyInstaller packaging, scheduled runs.

**[`PROJECT.md`](./PROJECT.md) is the source of truth** for design and scope.
Read it before non-trivial work. Section references below (§) point into it.

## Commands

```bash
# setup (one time)
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# run the TUI (configure a tool + run with live output)
pentui                                  # or: python -m pentui.cli
textual run --dev src/pentui/app.py     # dev mode with inspector
textual console                         # live log/event console (separate terminal)

# tests
pytest                                          # all
pytest tests/unit/test_db.py                    # one file
pytest tests/unit/test_db.py::test_init_db_creates_schema   # one test

# quality (run before committing)
ruff check .        # lint
ruff format .       # format
mypy src            # type check (strict)
```

## Architecture

Strictly layered. The **Workflow Engine** orchestrates multi-tool runs; the
**unified data model** (`Host → Port → Service`, plus `Finding`) is the shared
substrate that makes automated tool-to-tool handoff possible.

```
TUI (Textual)  →  Core (engine)  →  Persistence (SQLite) + Reporting
```

- `src/pentui/core/` — tool-agnostic engine: `models.py` (domain models),
  `manifest.py` (tool schema/loader, §5), `workflow.py` (DAG engine, §7),
  `query.py` (data-handoff selector, §7.2), `executor.py` (argv build + async
  run, §9), `scan_manager.py` (concurrency), `scope.py` (scope guardrail, §10),
  `registry.py` (discovery).
- `src/pentui/parsers/` — `base.py` defines the `Parser` protocol (§6); each tool
  gets a parser registered by name (e.g. `nmap_xml.py`).
- `src/pentui/persistence/` — `db.py` (connection + ordered migrations, §8),
  `repositories.py` (model↔row CRUD).
- `src/pentui/reporting/` — exporters for Markdown/HTML/JSON/CSV (§12).
- `src/pentui/tui/` — Textual screens/widgets (§11).
- `tools/`, `workflows/` — declarative YAML (also loaded from
  `~/.config/pentui/{tools,parsers,workflows}/`). Adding a simple tool is a new
  manifest, not code.

## Conventions & invariants (do not violate)

- **Core never imports Textual.** `pentui.core` and `pentui.persistence` must
  stay UI-free so the engine is testable headless and reusable. The dependency
  arrow only points TUI → core.
- **Build commands as argv lists — never shell strings, never `shell=True`.**
  Validate `value`/`choice` inputs and workflow-materialized targets before they
  reach argv (command-injection safety, §9).
- **Scope is a hard guardrail.** Out-of-scope targets are never scanned — blocked
  for manual runs (logged override), skipped-and-logged for workflow steps, even
  when a run is unattended (§10, §14).
- **Privileges are per-command.** The app runs unprivileged; only commands whose
  manifest options/profiles set `requires_root` get elevated via `sudo`, and that
  elevation is recorded in `audit_log`.
- **Schema changes are additive migrations.** Append to `MIGRATIONS` in
  `persistence/db.py`; never edit a shipped migration. Keep `core/models.py` in
  sync with the schema.
- **Hosts dedupe by `(project_id, ip)`; ports by `(host_id, number, protocol)`.**
  Repeat scans/steps enrich existing hosts rather than duplicating them.
- **Engagement data is sensitive recon** — `*.db` and `scans/` are git-ignored;
  never commit them.

## Build phases (see §16)

0 skeleton · 1 run a tool (manifest + executor) · 2 normalize (nmap_xml parser) ·
3 engagements & scope · **4 orchestration ★** (query + workflow DAG + gates) ·
5 reporting · 6 polish. When implementing a stubbed module, its docstring names
the phase and the intended API.
