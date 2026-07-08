#!/usr/bin/env bash
#
# deploy.sh — install pentui on a fresh Linux workstation.
#
# pentui is a hatchling-packaged Python app; its tool manifests and workflows
# are bundled into the wheel, so an install carries everything the engine needs.
# This script handles the host prerequisites the wheel can't: a recent enough
# Python, an isolated install (pipx, or a plain venv), and — optionally — the
# external CLI tools pentui orchestrates.
#
# Usage:
#   ./deploy.sh                 # pipx install from this repo
#   ./deploy.sh --with-tools    # also apt-install the wrapped CLI tools
#   ./deploy.sh --venv          # install into ./.venv instead of pipx
#   ./deploy.sh --dev           # editable venv install + dev extras (pytest/ruff/mypy)
#   ./deploy.sh --configure     # after install, run the interactive setup wizard
#                               # (Nessus keys, scan-output root, theme); on its own
#                               # against an existing install it just (re)configures
#   ./deploy.sh --help
#
# Per-user data lives outside this repo and is never touched:
#   ~/.local/share/pentui/   engagement DBs, scan artifacts, reports
#   ~/.config/pentui/        settings + your own tools/ and workflows/ overrides
#
set -euo pipefail

# --- locate the repo (script works from any cwd) ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MIN_PY_MINOR=11          # requires-python >= 3.11 (see pyproject.toml)
MODE="pipx"              # pipx | venv | dev
WITH_TOOLS=0
DO_CONFIGURE=0           # run the interactive setup wizard after install

# External binaries pentui wraps -> Debian/Kali apt package that provides them.
# (nessuscli is proprietary Tenable Nessus — install it manually if you need it.)
declare -A TOOL_PKGS=(
  [nmap]=nmap
  [masscan]=masscan
  [gowitness]=gowitness
  [nxc]=netexec
  [responder]=responder
  [ntlmrelayx.py]=python3-impacket
  [mitm6]=mitm6
  [nslookup]=dnsutils
)

# --- pretty output ---------------------------------------------------------
c_blue=$'\033[1;34m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_off=$'\033[0m'
info()  { printf '%s==>%s %s\n'  "$c_blue" "$c_off" "$*"; }
ok()    { printf '%s ok %s %s\n' "$c_grn"  "$c_off" "$*"; }
warn()  { printf '%s !! %s %s\n' "$c_yel"  "$c_off" "$*" >&2; }
die()   { printf '%serr%s %s\n'  "$c_red"  "$c_off" "$*" >&2; exit 1; }

usage() { sed -n '2,/^set -euo/{ /^set -euo/d; s/^# \{0,1\}//; p }' "$0"; exit 0; }

# --- args ------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --with-tools) WITH_TOOLS=1 ;;
    --venv)       MODE="venv" ;;
    --dev)        MODE="dev" ;;
    --configure)  DO_CONFIGURE=1 ;;
    -h|--help)    usage ;;
    *) die "unknown argument: $arg (try --help)" ;;
  esac
done

# --- python check ----------------------------------------------------------
find_python() {
  for cand in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && \
       "$cand" -c "import sys; sys.exit(0 if sys.version_info >= (3, $MIN_PY_MINOR) else 1)" 2>/dev/null; then
      command -v "$cand"; return 0
    fi
  done
  return 1
}

PYTHON="$(find_python || true)"
[ -n "$PYTHON" ] || die "need Python 3.$MIN_PY_MINOR+ on PATH. Install it (e.g. 'sudo apt install python3') and re-run."
ok "using $($PYTHON --version) at $PYTHON"

# --- optional: external CLI tools -----------------------------------------
install_tools() {
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "--with-tools needs apt (Debian/Kali). Install the wrapped tools manually on this distro."
    return
  fi
  local missing=()
  for bin in "${!TOOL_PKGS[@]}"; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("${TOOL_PKGS[$bin]}")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    ok "all wrapped CLI tools already present"
    return
  fi
  # de-dup package list
  mapfile -t missing < <(printf '%s\n' "${missing[@]}" | sort -u)
  info "installing wrapped tools: ${missing[*]}"
  sudo apt-get update -qq
  # install individually so one unavailable package doesn't abort the rest
  for pkg in "${missing[@]}"; do
    sudo apt-get install -y "$pkg" || warn "could not install '$pkg' — pentui will flag it as unavailable"
  done
}

[ "$WITH_TOOLS" -eq 1 ] && install_tools

# When `--configure` is the *only* flag and pentui is already installed, skip the
# (re)install and just run the wizard — so updating keys later doesn't reinstall.
RUN_INSTALL=1
if [ "$DO_CONFIGURE" -eq 1 ] && [ "$#" -eq 1 ] && command -v pentui >/dev/null 2>&1; then
  RUN_INSTALL=0
  info "pentui already installed — skipping install, configuring only"
fi

# --- install pentui --------------------------------------------------------
ensure_pipx() {
  if command -v pipx >/dev/null 2>&1; then return 0; fi
  info "installing pipx"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y pipx
  else
    "$PYTHON" -m pip install --user pipx
  fi
  "$PYTHON" -m pipx ensurepath >/dev/null 2>&1 || pipx ensurepath >/dev/null 2>&1 || true
}

if [ "$RUN_INSTALL" -eq 1 ]; then
case "$MODE" in
  pipx)
    ensure_pipx
    info "pipx install . (bundles tool manifests + workflows)"
    if pipx list 2>/dev/null | grep -q '\bpentui\b'; then
      pipx install --force .
    else
      pipx install .
    fi
    ;;
  venv)
    info "creating venv at ./.venv"
    "$PYTHON" -m venv .venv
    ./.venv/bin/pip install --upgrade pip >/dev/null
    ./.venv/bin/pip install .
    ok "installed into ./.venv — activate with: source .venv/bin/activate"
    ;;
  dev)
    info "creating dev venv at ./.venv (editable + dev extras)"
    "$PYTHON" -m venv .venv
    ./.venv/bin/pip install --upgrade pip >/dev/null
    ./.venv/bin/pip install -e ".[dev]"
    ok "editable install in ./.venv — activate with: source .venv/bin/activate"
    ;;
esac

# --- verify ----------------------------------------------------------------
echo
if [ "$MODE" = "pipx" ]; then
  if command -v pentui >/dev/null 2>&1; then
    ok "pentui installed: $(command -v pentui)"
    info "run it with:  pentui"
  else
    warn "pentui installed via pipx but not on PATH yet."
    warn "open a new shell, or run:  pipx ensurepath && exec \$SHELL -l"
  fi
else
  ok "pentui installed in venv"
  info "run it with:  source .venv/bin/activate && pentui"
fi
fi   # RUN_INSTALL

# --- optional: interactive configuration -----------------------------------
# Locate the just-installed pentui and run its `configure` wizard, so global
# settings (Nessus keys, scan-output root, theme) are provisioned before the
# first engagement — auto-launched recon workflows pick the keys up from there.
configure_pentui() {
  local bin=""
  case "$MODE" in
    venv|dev) [ -x "$SCRIPT_DIR/.venv/bin/pentui" ] && bin="$SCRIPT_DIR/.venv/bin/pentui" ;;
  esac
  [ -n "$bin" ] || bin="$(command -v pentui 2>/dev/null || true)"
  [ -n "$bin" ] || { [ -x "$HOME/.local/bin/pentui" ] && bin="$HOME/.local/bin/pentui"; }
  if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    warn "could not locate the pentui executable to configure; run 'pentui configure' manually."
    return
  fi
  echo
  info "configuring pentui (Nessus keys, scan-output root, theme)"
  "$bin" configure || warn "configuration did not complete; run 'pentui configure' later."
}

[ "$DO_CONFIGURE" -eq 1 ] && configure_pentui

cat <<'EOF'

Next steps
  - Set or update global settings (Nessus keys, scan-output root, theme) anytime:
        pentui configure
  - Root-requiring tools (masscan, responder, SYN scans) prompt once per
    session for sudo and elevate per-command. To run the whole app as root:
        sudo -E env "PATH=$PATH" "$(command -v pentui)"
  - Engagement data (DBs, scans, reports) is created under
    ~/.local/share/pentui/ on first use — back that up, not this repo.
  - Update later:  git pull && ./deploy.sh
EOF
