#!/usr/bin/env bash
# repcollect install.sh — sets up rpt and repkit in one shot

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
BASHRC="$HOME/.bashrc"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
err()  { echo -e "${RED}[error]${NC} $*"; }


echo "setting up repcollect..."

# ── Python venv + rpt ──────────────────────────────────────────────────────

if ! command -v python3 &>/dev/null; then
    err "python3 is required."
    exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install -e "$REPO_DIR" -q
ok "rpt installed"

# ── Add venv activation to ~/.bashrc ──────────────────────────────────────

ACTIVATE_LINE="source $VENV_DIR/bin/activate"
if ! grep -qF "$ACTIVATE_LINE" "$BASHRC" 2>/dev/null; then
    echo "" >> "$BASHRC"
    echo "# repcollect" >> "$BASHRC"
    echo "$ACTIVATE_LINE" >> "$BASHRC"
    ok "added rpt to shell (source ~/.bashrc or open a new terminal)"
else
    ok "shell activation already in ~/.bashrc"
fi

# ── repkit ─────────────────────────────────────────────────────────────────

REPKIT_INSTALL="$REPO_DIR/repkit/install.sh"
if [[ -f "$REPKIT_INSTALL" ]]; then
    chmod +x "$REPKIT_INSTALL"
    bash "$REPKIT_INSTALL"
else
    warn "repkit/install.sh not found, skipping"
fi

# ── Done ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════"
echo " all done."
echo "══════════════════════════════════════════════"
echo ""
echo " run:  source ~/.bashrc"
echo " then: eng new <target>"
echo "       rpt run -t ext -p recon"
echo ""
