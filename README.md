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
work (`PROJECT.md` §14): parallel execution of independent branches, SQLCipher
encryption, PyInstaller packaging, scheduled runs.

Workflows are authored as **declarative YAML** (bundled under
`src/pentui/workflows/`, or your own in `~/.config/pentui/workflows/`) and
launched from the Workflows screen. Adding a manifest under
`src/pentui/tools/` (or the user dir) makes the tool show up everywhere
automatically. On the scan screen you
can **save a configured scan as a named profile** (written to
`~/.config/pentui/tools/`, merged with the tool's existing profiles). Pointing a
file-input option (e.g. gowitness `-f`) at a **directory** runs the tool once per
matching file. Workflows can **fan out per /24** (`foreach: subnet/24`) and hand a
downstream tool the **collected artifacts** of an upstream step (`file_from`) —
see the shipped `engagement-recon` workflow (masscan → per-/24 nmap → gowitness,
then dc-discovery/smb/relay branches off the one nmap),
whose per-/24 nmap scans run **bounded-parallel** (`max_parallel`, else
`max_concurrent_scans`, default 4). Creating an engagement can **auto-launch a
workflow unattended** via the *"Run workflow on create"* dropdown (set initial
targets first); the monitor bells + notifies when the chain finishes. A
running scan or workflow step can be stopped with `s`. Shipped tool manifests: nmap, masscan,
nslookup, gowitness, nxc, responder, ntlmrelayx, mitm6, nessus.

The UI is keyboard-first: `↑`/`↓` move focus between fields (so you can jump back
to an earlier textbox without Tab-cycling), while `Tab`/`Shift+Tab` still work and
lists/tables/trees keep their native arrow navigation.

## Quick start (development)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

pentui                 # launch the TUI
pytest                 # run tests
ruff check . && mypy src
```

## Install on another machine (Kali)

**Fastest path — `deploy.sh`** handles all of the below (Python check, pipx,
optional CLI tools) in one command:

```bash
./deploy.sh                # pipx install from this repo
./deploy.sh --with-tools   # also apt-install the wrapped CLI tools
./deploy.sh --venv         # install into ./.venv instead of pipx
./deploy.sh --dev          # editable venv + dev extras (pytest/ruff/mypy)
./deploy.sh --help
```

The manual steps it automates are below.

`pentui` needs Python 3.11+ and the CLI tools it wraps (`nmap`, `masscan`,
`gowitness`, `netexec`/`nxc`, `responder`, `impacket`/`ntlmrelayx`, `mitm6`, …);
install those via `apt`/`pipx` as needed — pentui only orchestrates them, and
unavailable tools are flagged in the UI.

Recommended (isolated CLI install with [pipx]):

```bash
sudo apt install -y pipx          # if not present
# copy the repo to the target (git clone from your team remote, or scp/rsync):
#   rsync -a --exclude .venv --exclude '*.db' nmapTUI/ user@host:~/nmapTUI/
cd ~/nmapTUI
pipx install .                    # bundles the tool manifests + workflows
pentui                            # on PATH for that user
# later: cd ~/nmapTUI && git pull && pipx reinstall pentui
```

Or a plain venv:

```bash
cd ~/nmapTUI
python3 -m venv .venv && source .venv/bin/activate
pip install .                     # (or -e . for development)
pentui
```

Per-user data lives under `~/.local/share/pentui/` (engagements: SQLite DBs,
scan artifacts, reports) and `~/.config/pentui/` (settings, and your own
`tools/`/`workflows/` overrides). Don't copy `.venv/` or `*.db` between machines.
Root-requiring tools (masscan, responder, `-sS`, …) prompt once per session for
your sudo password and elevate per-command via `sudo -S` (password fed on stdin,
never written to disk; **F3** clears the cached password). Alternatively run the
whole app as root
(`sudo -E env "PATH=$PATH" "$(which pentui)"`) to skip the prompt.
