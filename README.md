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

All six build phases are implemented. Engagements hold scope rules and targets;
tools run from YAML manifests with live output and the scope guardrail; results
are parsed into the unified Host→Port→Service model, persisted, and browsed; a
**workflow engine** chains tools as a branching DAG — one tool's results feed the
next through the data-handoff query layer (e.g. *hosts with open 80/443 →
gowitness URLs*), with approval gates and an unattended mode; engagements
**export to Markdown/HTML/JSON/CSV**; and the UI has blue/white + colour-blind-safe
themes (F2), tool-availability hints, and an audit-log viewer. Deferred to future
work (`PROJECT.md` §14): parallel step execution, SQLCipher encryption, PyInstaller
packaging, scheduled runs.

## Quick start (development)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pentui                 # launch the TUI (placeholder in Phase 0)
pytest                 # run tests
ruff check . && mypy src
```
