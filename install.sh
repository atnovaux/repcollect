#!/usr/bin/env bash
# repcollect install.sh — sets up rpt and repkit in one shot

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"

SHELL_RCS=()
[[ -f "$HOME/.bashrc" ]] && SHELL_RCS+=("$HOME/.bashrc")
[[ -f "$HOME/.zshrc" ]]  && SHELL_RCS+=("$HOME/.zshrc")
[[ ${#SHELL_RCS[@]} -eq 0 ]] && SHELL_RCS=("$HOME/.bashrc")

add_to_shell_rcs() {
    local pattern="$1" line="$2" rc
    for rc in "${SHELL_RCS[@]}"; do
        if ! grep -qF "$pattern" "$rc" 2>/dev/null; then
            echo "$line" >> "$rc"
        fi
    done
}

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
for rc in "${SHELL_RCS[@]}"; do
    if ! grep -qF "$ACTIVATE_LINE" "$rc" 2>/dev/null; then
        {
            echo ""
            echo "# repcollect"
            echo "$ACTIVATE_LINE"
        } >> "$rc"
        ok "added rpt to $(basename "$rc")"
    else
        ok "rpt already in $(basename "$rc")"
    fi
done

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
echo " run:  source ~/.bashrc  (or ~/.zshrc if you use zsh)"
echo " then: eng new <target>"
echo "       rpt run -t ext -p recon"
echo ""
