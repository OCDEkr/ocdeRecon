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

Workflows can be authored two ways: hand-written YAML under `workflows/` (or
`~/.config/pentui/workflows/`), or **built interactively** in the app — press
`b` on the Workflows screen to chain tools (pick a tool + profile, choose what
each step feeds on, mark gates) and save a reusable workflow. Each step shows a
**live command preview** and takes an **extra-args** field, so you're not limited
to profiles — you see and tweak the exact command that will run. Adding a manifest
under
`tools/` makes the tool show up everywhere automatically. On the scan screen you
can **save a configured scan as a named profile** (written to
`~/.config/pentui/tools/`, merged with the tool's existing profiles). Pointing a
file-input option (e.g. gowitness `-f`) at a **directory** runs the tool once per
matching file. Workflows can **fan out per /24** (`foreach: subnet/24`) and hand a
downstream tool the **collected artifacts** of an upstream step (`file_from`) —
see the shipped `subnet-recon` workflow (masscan → per-/24 nmap → gowitness). A
running scan or workflow step can be stopped with `s`. Shipped tool manifests: nmap, masscan,
nslookup, gowitness, nxc, responder, ntlmrelayx, mitm6, nessus.

## Quick start (development)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pentui                 # launch the TUI (placeholder in Phase 0)
pytest                 # run tests
ruff check . && mypy src
```
