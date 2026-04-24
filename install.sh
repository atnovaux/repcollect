#!/usr/bin/env bash
# repcollect install.sh — sets up rpt and repkit in one shot

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
ZSHRC="$HOME/.zshrc"

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

# ── Add venv activation to ~/.zshrc ───────────────────────────────────────

ACTIVATE_LINE="source $VENV_DIR/bin/activate"
if ! grep -qF "$ACTIVATE_LINE" "$ZSHRC" 2>/dev/null; then
    {
        echo ""
        echo "# repcollect"
        echo "$ACTIVATE_LINE"
    } >> "$ZSHRC"
    ok "added rpt to ~/.zshrc"
else
    ok "rpt already in ~/.zshrc"
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
echo " next steps:"
echo "   1. source ~/.zshrc"
echo "   2. rpt new <target>   — create your first engagement"
echo "   3. rpt use <target>   — set the active engagement"
echo "   4. rpt run -t ext -p recon   — run your first phase"
echo ""
