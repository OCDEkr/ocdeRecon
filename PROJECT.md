# Project Specification — Offensive Security Automation TUI

> A terminal user interface (TUI) that wraps command-line offensive-security
> tools and **chains them into automated workflows**. Built for a cybersecurity
> department running authorized penetration tests, its primary purpose is to
> **reduce manual input** — one tool's output automatically feeds the next.
> **Nmap is the proof of concept**, but the architecture treats every tool as a
> pluggable component and every multi-tool process as a definable workflow.

Working name: `pentui` (package) — final product name TBD. The repo directory
is currently `nmapTUI`.

---

## 1. Goals & Non-Goals

### Goals
- **Automate multi-tool workflows** so operators don't hand-start each step.
  *Example:* an nmap scan discovers hosts; web ports automatically flow into
  gowitness; SMB ports flow into an enumeration tool — no human in between.
- One TUI to drive many CLI tools with a **consistent workflow** per tool.
- **Add or remove tools without touching core code** — a tool is a declarative
  manifest plus an optional output parser.
- Normalize every tool's output into a **shared data model** — this is what makes
  automated handoff between arbitrary tools possible.
- Organize work by **engagement/project**, with target lists and history.
- **Guardrails for authorized testing**: enforce scope, log overrides/elevation.
- Produce **client-ready reports** (Markdown, HTML, JSON, CSV).

### Non-Goals (for now)
- Remote agent / distributed scanning. The PoC runs **locally on the operator's box**.
- Multi-user/shared concurrent access to one engagement.
- Reimplementing tool capabilities — we orchestrate, we don't replace.

---

## 2. Key Decisions (locked in)

| Area | Decision | Rationale |
|------|----------|-----------|
| **Automation** | **First-class workflow engine** chaining tools | The core purpose: cut manual input. |
| Workflow shape | **Branching DAG** (fan-out + parallel steps) | Matches real recon trees (one scan feeds several tools). |
| Data handoff | **Query the unified model** (e.g. "hosts with open 80/443 → gowitness") | Tool-agnostic; any upstream tool that fills the model can feed any downstream tool. |
| Automation level | **Auto by default with optional gates**; a **per-run "unattended" flag** suppresses gates for that session | Unattended speed when wanted, approval checkpoints when needed. |
| Workflow authoring | **Declarative YAML + TUI builder** | Shareable/versionable templates, plus interactive assembly. |
| Language / TUI | **Python 3.11+ with [Textual](https://textual.textualize.io/)** | Fast iteration; pentesters know Python; rich widgets. |
| Tool extensibility | **Declarative YAML manifests** | Add a simple tool = drop in a file, no recompile. |
| Output parsing | **Manifest names a parser; parsers are Python plugins** | Simple tools need only a manifest; complex output gets a small parser. |
| Data model | **Unified schema** — `Host → Port → Service`, plus `Finding` | Cross-tool correlation + the substrate for automated handoff. |
| Persistence | **SQLite**, one DB file per engagement | Queryable, supports history/correlation, no server. |
| Reporting | **Markdown, HTML, JSON, CSV** | Human deliverables + machine pipelines. |
| Environment | **Local operator box (Kali)** | Direct execution; handles tools needing root. |
| Privileges | **Per-scan `sudo` prompt**; manifests flag `requires_root` | App runs unprivileged; elevate only the commands that need it. |
| Run config | **Manifest-defined profiles + manual override** | Fast common scans, flexible when needed. |
| Scope safety | **Enforce scope with logged override** | Critical guardrail for authorized pentests. |
| Target input | Manual, file import, project list, **and from prior results** | Feeds both manual runs and automated workflows. |

---

## 3. Architecture Overview

Layered. The **Workflow Engine** sits above the executor and orchestrates
multi-tool runs; the unified data model is the shared substrate that makes
tool-to-tool handoff possible.

```
┌──────────────────────────────────────────────────────────────────┐
│ TUI (Textual)                                                      │
│  Project select · Dashboard · Tool config · Workflow builder ·     │
│  Workflow/scan monitor · Results browser · Report export           │
└───────────────┬────────────────────────────────────────────────────┘
                │ calls
┌───────────────▼────────────────────────────────────────────────────┐
│ Core (tool-agnostic, no Textual imports)                            │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────┐      │
│   │ WorkflowEngine   DAG schedule · gates · unattended flag    │      │
│   │   uses ▸ Query (select inputs from unified model)          │      │
│   │   uses ▸ ScanManager → Executor (per-step runs)            │      │
│   └──────────────────────────────────────────────────────────┘      │
│                                                                      │
│  • Registry   load manifests + parser plugins + workflow defs        │
│  • Manifest   tool schema/validation (Pydantic)                      │
│  • Executor   build argv · scope-check · sudo · async stream         │
│  • ScanManager  concurrency / queue of running steps                 │
│  • Scope      in/out-of-scope decisions + override logging           │
│  • Query      safe selector over normalized results (data handoff)   │
│  • Parsers    raw output → normalized ScanResult                     │
│  • Models     Host/Port/Service/Finding/Scan/Project/Target/Workflow │
└───────────────┬────────────────────────────────────────────────────┘
                │ persists / reads
┌───────────────▼────────────────────────────────────────────────────┐
│ Persistence (SQLite per engagement) + Reporting (Jinja2/CSV)        │
└──────────────────────────────────────────────────────────────────────┘
```

**Hard rule:** `core/` and `persistence/` never import Textual. The TUI depends
on core; core never depends on the TUI. This keeps the engine (and the workflow
runner especially) testable headless and reusable for a future CLI or
remote-agent mode.

---

## 4. Proposed Directory Layout

```
nmapTUI/
  pyproject.toml
  README.md
  PROJECT.md                 # this document
  src/pentui/
    cli.py                   # entry point → launches app
    app.py                   # Textual App
    config.py                # app config, data dirs, concurrency limits
    core/
      models.py              # Host, Port, Service, Finding, Scan, Project, Target,
                             #   Workflow, WorkflowRun, StepRun, ScanResult
      manifest.py            # ToolManifest schema + loader/validator
      workflow.py            # WorkflowDefinition schema + WorkflowEngine (DAG runner)
      query.py               # safe selector over the unified model (data handoff)
      registry.py            # discover/load manifests, parsers, workflow defs
      executor.py            # async subprocess runner: argv build, stream, sudo
      scan_manager.py        # tracks running steps, concurrency, queue
      scope.py               # scope rule evaluation + override audit
    parsers/
      base.py                # Parser protocol + ParseContext
      nmap_xml.py            # Nmap XML → ScanResult
    persistence/
      db.py                  # connection, schema/migrations
      repositories.py        # CRUD per entity
    reporting/
      exporter.py            # MD/HTML/JSON/CSV
      templates/
    tui/
      screens/
        project_select.py
        dashboard.py
        tool_config.py       # profile picker + options form + live command preview
        workflow_builder.py  # assemble/launch workflows (DAG)
        workflow_monitor.py  # DAG view: per-step status, gate approvals, live output
        results.py           # host tree → ports → services; findings
        report.py            # export wizard
      widgets/
  tools/                     # shipped tool manifests
    nmap.yaml
  workflows/                 # shipped workflow definitions
    web-recon.yaml
  tests/
    unit/                    # core logic, parsers, scope, query, workflow engine
    tui/                     # Textual Pilot-driven UI tests
    fixtures/                # sample nmap XML, manifests, workflows
```

User-supplied manifests, parsers, and workflows also load from a user config dir
(e.g. `~/.config/pentui/{tools,parsers,workflows}/`) so the team can extend and
share without editing the package.

---

## 5. Tool Manifest Specification

Describes how to build a command, what needs root, the profiles offered, and the
parser for its output. Validated with Pydantic on load; invalid manifests are
skipped with a clear error.

```yaml
# tools/nmap.yaml
name: nmap
binary: nmap                       # resolved on PATH; presence checked at load
description: "Network mapper / port & service scanner"
version_check: ["nmap", "--version"]

target:
  mode: append                     # append | flag  (how targets enter the argv)
  # flag: "-iL"                    # if mode: flag, write a target file & pass it

output:
  stream: stdout                   # shown live in the monitor
  artifact:                        # optional structured artifact for the parser
    flag: "-oX"
    path: "{scan_dir}/nmap.xml"    # {scan_dir} injected per-scan
  parser: nmap_xml                 # → parsers/nmap_xml.py registered as "nmap_xml"

options:
  - {flag: "-sS", label: "TCP SYN scan", type: bool, group: "Scan type", requires_root: true}
  - {flag: "-sT", label: "TCP connect scan", type: bool, group: "Scan type"}
  - {flag: "-sV", label: "Service/version detection", type: bool}
  - {flag: "-O",  label: "OS detection", type: bool, requires_root: true}
  - {flag: "-p",  label: "Ports", type: value, placeholder: "22,80,443 or 1-65535", validate: ports}
  - {flag: "-T",  label: "Timing template", type: choice, choices: ["0","1","2","3","4","5"], default: "4"}

profiles:
  - {name: "Quick",        description: "Fast scan of common ports", args: ["-T4", "-F"]}
  - {name: "Service scan", description: "Versions + default scripts", args: ["-sV", "-sC", "-T4"]}
  - {name: "Full TCP",     description: "All TCP ports, SYN scan", args: ["-sS", "-p-", "-T4"], requires_root: true}
```

**Option `type`s:** `bool`, `value` (flag + string), `choice` (flag + one of
`choices`). `requires_root` on an option or profile is unioned into the final
command's elevation decision. The downstream side of automation also relies on
`target.mode` — the workflow engine materializes selected results into targets
using it (see §7).

---

## 6. Parser Plugin Contract

Parsers are small, pure functions: raw output in, normalized `ScanResult` out.
No DB access, no UI — the core persists the result, which then becomes available
to the workflow query layer.

```python
# parsers/base.py
from typing import Protocol
from pentui.core.models import ScanResult

class ParseContext:
    raw_stdout: str
    raw_stderr: str
    artifact_path: str | None      # e.g. the nmap XML file, if any
    scan_id: int
    project_id: int

class Parser(Protocol):
    name: str                       # matches manifest output.parser
    def parse(self, ctx: ParseContext) -> ScanResult: ...
```

`ScanResult` holds normalized `Host`/`Port`/`Service`/`Finding` objects (not yet
persisted). The core merges it into the engagement DB, deduping hosts by IP
within the project.

---

## 7. Workflow & Orchestration Engine  ★ core purpose

This is the reason the project exists: chain tools so operators don't manually
start each step.

### 7.1 Model — a branching DAG
A **workflow** is a set of **steps**; each step names a tool (+ profile/options)
and declares which steps it runs `after`. Edges form a directed acyclic graph,
so one upstream step can fan out to several downstream tools, and independent
branches run in parallel (subject to concurrency limits).

### 7.2 Data handoff — query the unified model
A step gets its targets either from the project list or by **querying normalized
results** produced upstream. Because every tool writes into the same
`Host/Port/Service/Finding` model, any tool can feed any other — no per-pair
adapters.

```yaml
# workflows/web-recon.yaml
name: web-recon
description: "Discover hosts, screenshot web services, enumerate SMB"
defaults:
  gates: true                      # honor gates unless the run is unattended
steps:
  - id: discover
    tool: nmap
    profile: "Quick"
    targets: {from: project}       # use the engagement's target list

  - id: web-shots
    tool: gowitness
    after: [discover]
    input:
      from: hosts
      where: {port_open_in: [80, 443, 8080, 8443]}
      as: target_urls              # host+port → http(s)://host:port
    gate: false                    # runs automatically

  - id: smb-enum
    tool: smb-enum
    after: [discover]
    input:
      from: hosts
      where: {port_open_in: [445]}
      as: targets
    gate: true                     # pause for operator approval first

  - id: service-scan
    tool: nmap
    profile: "Service scan"
    after: [discover]
    input: {from: hosts, where: {state: up}, as: targets}
```

**Query language (`core/query.py`)** — a small, safe, *non-arbitrary* selector
(not raw SQL). Planned conditions: `port_open_in`, `service_name_in`,
`hostname_matches`, `has_finding_severity`, `state`, combinable with and/or.
**`as`** is a named materializer that turns selected entities into the
downstream tool's input, applying transforms (e.g. `target_urls` builds URLs
from host+port; `targets` emits IPs/hostnames; `ip_list`/file output for
`target.mode: flag`). Materializers are extensible.

### 7.3 Gates & the unattended flag
- A step (or the workflow default) may set `gate: true` → the engine **pauses
  for operator approval** before that step runs.
- **Implicit gates** always apply regardless of config: a step whose command
  `requires_root`, or whose materialized targets fall outside scope.
- A **per-run "unattended" flag** (TUI toggle / `--unattended`) suppresses
  *approval* gates for that session and auto-confirms sudo elevation — every such
  auto-confirmation is written to `audit_log`.
- **Scope remains a hard guardrail even when unattended:** out-of-scope targets
  are **skipped and logged**, never silently scanned. (Policy detail to confirm —
  see §14.)

### 7.4 Runner (`WorkflowEngine`)
1. Parse + validate the workflow; build the DAG; reject cycles.
2. Topologically schedule: a step becomes *ready* when all `after` deps finish.
3. For each ready step, evaluate its `input` query against the DB, materialize
   targets, scope-check them.
4. Apply gates (unless unattended): pending steps wait for approval in the monitor.
5. Run ready steps via `ScanManager`/`Executor` (parallel within concurrency limit).
6. On step completion, parse → persist → unblock dependents.
7. **Failure policy** per step: `stop-branch` (default) or `continue`; a failed
   step marks its branch skipped but other branches proceed.
8. Persist `WorkflowRun`/`StepRun` state throughout for **resumability** and reporting.

---

## 8. Data Model & SQLite Schema

Normalized so any tool's results land in the same shape, correlate, and feed
workflows.

```
project (id, name, client, notes, created_at)
  └─ scope_rule (id, project_id, value, kind)            kind: include|exclude (CIDR/host)
  └─ target (id, project_id, value, source, added_at)    source: manual|file|chained|project
  └─ scan (id, project_id, tool, profile, command_str, args_json,
            status, exit_code, ran_as_root, started_at, finished_at,
            raw_output_path, artifact_path, step_run_id?) status: queued|running|done|error|cancelled
  └─ host (id, project_id, ip, hostname, state, first_seen, last_seen)   -- deduped by (project_id, ip)
       └─ port (id, host_id, discovered_by_scan_id, number, protocol, state, reason)
            └─ service (id, port_id, name, product, version, extrainfo, cpe)
  └─ finding (id, project_id, host_id, scan_id, source_tool, severity, title, detail, created_at)
  └─ workflow_run (id, project_id, workflow_name, definition_json, status,
                   unattended, started_at, finished_at)
       └─ step_run (id, workflow_run_id, step_id, tool, scan_id, status,
                    gate_state, started_at, finished_at)   gate_state: auto|pending|approved|skipped
  └─ audit_log (id, project_id, ts, action, detail)        -- scope overrides/skips, sudo runs, deletes
```

Notes:
- **Hosts are project-scoped and deduped** so repeat scans (and workflow steps)
  enrich the same host. `discovered_by_scan_id` keeps provenance on ports.
- A **scan links to its `step_run`** when produced by a workflow, tying
  automation runs back to concrete results.
- **Raw/artifact files** live on disk under the engagement's scan dir; the DB
  stays lean. Layout:
  `~/.local/share/pentui/engagements/<name>/engagement.db` plus
  `scans/<scan_id>/` (stdout log + artifacts like `nmap.xml`).
- **Library:** start with stdlib `sqlite3` + a thin repository layer; revisit
  SQLModel if relationship/query complexity grows (open — §14).

---

## 9. Execution Engine

`executor.py` + `scan_manager.py`, on `asyncio` (Textual is async). Used for both
manual single runs and individual workflow steps.

1. **Build argv as a list** — never a shell string, never `shell=True`:
   `[binary] + profile_args + option_args + artifact_flags + targets`.
   `value`/`choice` inputs pass named validators (e.g. `ports`) first.
2. **Scope check** (see §10) — expand targets, validate against scope rules.
3. **Privilege decision** — if any selected option/profile is `requires_root` and
   the process isn't root, prompt (or auto-confirm if the workflow run is
   unattended); prepend `sudo`; record `ran_as_root` + `audit_log`.
4. **Launch** via `asyncio.create_subprocess_exec`; stream stdout/stderr to the
   monitor and tee to `scans/<id>/stdout.log`.
5. **On exit** — run the manifest's parser, merge `ScanResult` into the DB,
   update status. The workflow engine then unblocks dependents.
6. **Concurrency** — `ScanManager` runs up to N steps at once (config, default 4);
   extras queue. Each is a cancellable Textual worker.

**Command-injection safety:** argv lists only; validate value inputs; reject
shell metacharacters in free-text that reaches argv. Workflow-materialized
targets are validated the same way before use.

---

## 10. Scope Enforcement

- Each project defines `scope_rule`s: `include`/`exclude` CIDRs or hosts.
- Before any scan or workflow step, targets are expanded and checked with
  Python's `ipaddress` module: must match an `include`, not match an `exclude`.
- Manual run, out-of-scope → **blocked**, with an explicit logged override path.
- Workflow step, out-of-scope target → **skipped and logged** (the rest of the
  step's in-scope targets proceed); never silently scanned.
- A project with **no** scope rules warns prominently.

---

## 11. TUI Flow (Textual)

1. **Project select / create** — engagement (name, client, scope, initial targets).
2. **Dashboard** — targets, recent scans + workflow runs, host-inventory summary,
   finding counts; launch point for scans, workflows, and reports.
3. **Tool config** — pick tool → profile → optional manual form, with a **live
   command preview** and target source (manual / file / project / prior results).
4. **Workflow builder** — assemble a DAG from steps (tool + profile + input
   query + gate), or load a YAML template; set the **unattended** toggle; launch.
5. **Workflow / scan monitor** — DAG view with per-step status; **approve gated
   steps** here; live streaming output per step (tabs); cancel/resume.
6. **Results browser** — host tree → ports → services; findings; filter/search;
   drill into a result's originating scan/step.
7. **Report export** — choose format(s) + scope, generate, show output path.

Use Textual dev tooling while building: `textual run --dev` and `textual console`.

---

## 12. Reporting

Pulls normalized data from the engagement DB:
- **Markdown / HTML** via Jinja2 templates; HTML self-contained (inline CSS).
- **JSON** — full structured dump for downstream tooling.
- **CSV** — flat findings and/or host:port:service inventory (stdlib `csv`).

Reports state engagement, scope, date range, tools/commands run, and — for
automated runs — the **workflow and its steps** (traceability for deliverables).

---

## 13. Nmap Proof-of-Concept — Definition of Done

The PoC validates both the **tool-plugin model** and the **orchestration model**.
Done when, entirely from the TUI, an operator can:
1. Create an engagement with scope rules and targets.
2. Pick **Nmap**, choose a profile or tweak flags manually, with live preview.
3. Get a **sudo prompt** for a root-only option (e.g. `-sS`, `-O`).
4. Be **blocked** when targeting an out-of-scope host (logged override path).
5. Watch **live output** stream during the scan.
6. See results parsed from **nmap XML** into the host/port/service browser.
7. **Export** to Markdown, HTML, JSON, and CSV.
8. **Run a 2-step workflow** — nmap discovery → a second tool fed by querying the
   results (the canonical `nmap → gowitness on web ports` chain) — with a gate
   and with the unattended flag, proving automated handoff end to end.
9. Add the **second tool by manifest** (+ parser if needed), proving extensibility.

---

## 14. Resolved Decisions & Deferred Work

### Resolved
- **Unattended + scope policy:** out-of-scope targets are **always skipped and
  logged**, never scanned — even with the unattended flag. No silent scanning of
  anything outside the engagement's scope rules. (No pre-authorized override list
  for unattended runs.)
- **Product name:** keep working name **`pentui`** for now.
- **Query language (initial set):**
  - `where` conditions: `port_open_in`, `service_name_in`, `state`,
    `has_finding_severity`, `hostname_matches` — combinable with and/or.
  - `as` materializers: `targets` (IPs/hostnames), `target_urls`
    (host+port → http/https URL), `ip_list`/file (for `target.mode: flag`).
  - Kept deliberately non-arbitrary (no raw SQL / no eval); extend the named
    condition/materializer sets as needs arise.
- **Persistence library:** stdlib **`sqlite3` + a thin repository layer** to
  start; revisit SQLModel only if relationship/query complexity grows.
- **DB encryption at rest:** rely on **OS-level protection** (LUKS / file perms)
  for the PoC and document it; revisit **SQLCipher** (passphrase-protected
  engagements) in a later phase.
- **Packaging:** **`pipx install`** during development; add a **PyInstaller
  single-binary** build later to avoid per-box venv management.
- **Workflow resumability vs. scheduling:** **persist run state for resume from
  the start** (cheap — `StepRun` is stored anyway); **defer scheduled/recurring
  runs** entirely.
- **NSE / vuln → Findings (PoC):** capture NSE script output as **low-fidelity
  findings** (title + raw detail, severity `info`/`unknown`). Proper severity
  normalization is a later phase.
- **Theming:** default **blue-and-white** palette, with an **optional
  color-blind-safe palette** selectable by the operator. Keybindings/broader
  accessibility use Textual defaults for now.

### Deferred to later phases
- SQLCipher encrypted engagements (passphrase to open).
- PyInstaller single-binary distribution.
- Scheduled / recurring workflow runs.
- Severity normalization for vuln findings; richer NSE mapping.
- Custom keybindings and broader accessibility polish.

---

## 15. Tech Stack & Tooling

| Concern | Choice |
|--------|--------|
| Runtime | Python 3.11+ |
| TUI | Textual |
| Manifests / workflows | PyYAML |
| Validation / models | Pydantic |
| Templating | Jinja2 |
| Persistence | SQLite (stdlib `sqlite3` to start) |
| Subprocess / concurrency | `asyncio` |
| Tests | pytest + Textual Pilot |
| Lint / format | ruff (+ `ruff format`) |
| Type checking | mypy |
| Packaging | `pyproject.toml` (PEP 621); entry point `pentui` |

### Anticipated dev commands (define in `pyproject.toml`)
```bash
# setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# run
pentui                       # or: python -m pentui
textual run --dev src/pentui/app.py    # dev mode w/ inspector
textual console              # live log/event console (separate terminal)

# tests
pytest
pytest tests/unit/test_workflow_engine.py::test_fan_out   # single test

# quality
ruff check .
ruff format .
mypy src
```

---

## 16. Suggested Build Phases

Automation is the headline capability, but it depends on the data model,
executor, and scope layers — so it lands once those exist (a 2-step linear chain
can be prototyped as soon as Phase 2 is done).

- **Phase 0 — Skeleton:** `pyproject.toml`, package layout, config/paths, data
  models, SQLite schema + migrations, CI (ruff/mypy/pytest).
- **Phase 1 — Run a tool:** manifest loader + `nmap.yaml`, executor (argv build,
  async streaming, sudo prompt), minimal TUI to launch and watch raw output.
- **Phase 2 — Normalize:** `nmap_xml` parser, persist into the unified model,
  results browser. *(Enables the first manual tool→tool handoff.)*
- **Phase 3 — Engagements & safety:** project/target management, scope
  enforcement, audit log.
- **Phase 4 — Orchestration ★:** `query.py` (data handoff), `workflow.py` DAG
  runner, gates + unattended flag, workflow builder + monitor screens. Prove with
  the `nmap → second tool` chain.
- **Phase 5 — Reporting:** Markdown/HTML/JSON/CSV exporters (incl. workflow runs).
- **Phase 6 — Polish:** more tools by manifest, concurrency/queue UX, themes
  (default blue-and-white + optional color-blind-safe palette), and the deferred
  items from §14 (SQLCipher, PyInstaller, scheduling).
```
