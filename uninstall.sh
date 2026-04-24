#!/usr/bin/env bash
# repcollect uninstall.sh — nuke everything installed by install.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"
BASHRC="$HOME/.bashrc"
TOOLS_DIR="$HOME/tools"
BIN_DIR="$HOME/bin"
REPKIT_DIR="$REPO_DIR/repkit"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
err()  { echo -e "${RED}[error]${NC} $*"; }

WIPE_ENGAGEMENTS=0
if [[ "${1:-}" == "--all" ]]; then
    WIPE_ENGAGEMENTS=1
fi

echo ""
echo "══════════════════════════════════════════════"
echo " repcollect uninstall"
echo "══════════════════════════════════════════════"
echo " will remove:"
echo "   - $VENV_DIR"
echo "   - $TOOLS_DIR (git clones + pytools_venv)"
echo "   - repkit wrapper symlinks in $BIN_DIR"
echo "   - ~/.dotnet (if installed by repkit)"
echo "   - repcollect lines in ~/.bashrc"
echo "   - ~/.engagement state file"
echo "   - go binaries: httpx, gowitness, ffuf, trufflehog, s3scanner"
if [[ $WIPE_ENGAGEMENTS -eq 1 ]]; then
    echo -e "   ${RED}- ~/engagements (ALL engagement data, --all flag given)${NC}"
else
    echo "   (keeping ~/engagements — use --all to wipe that too)"
fi
echo ""
read -rp "proceed? [y/N] " ans
if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
    echo "aborted."
    exit 0
fi

# ── rpt venv ───────────────────────────────────────────────────────────────

if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
    ok "removed $VENV_DIR"
fi

# ── ~/bin symlinks ─────────────────────────────────────────────────────────

if [[ -d "$REPKIT_DIR/wrappers" ]]; then
    for wrapper in "$REPKIT_DIR/wrappers/"*; do
        [[ -f "$wrapper" ]] || continue
        link="$BIN_DIR/$(basename "$wrapper")"
        if [[ -L "$link" ]]; then
            rm -f "$link"
            ok "removed symlink $link"
        fi
    done
fi
if [[ -L "$BIN_DIR/eng" ]]; then
    rm -f "$BIN_DIR/eng"
    ok "removed symlink $BIN_DIR/eng"
fi

# ── go binaries installed by repkit ───────────────────────────────────────

for bin in httpx gowitness ffuf trufflehog s3scanner; do
    if [[ -f "$HOME/go/bin/$bin" ]]; then
        rm -f "$HOME/go/bin/$bin"
        ok "removed ~/go/bin/$bin"
    fi
done

# ── tools dir (includes pytools_venv) ─────────────────────────────────────

if [[ -d "$TOOLS_DIR" ]]; then
    rm -rf "$TOOLS_DIR"
    ok "removed $TOOLS_DIR"
fi

# ── dotnet (only if installed by repkit script) ───────────────────────────

if [[ -d "$HOME/.dotnet" ]]; then
    rm -rf "$HOME/.dotnet"
    ok "removed ~/.dotnet"
fi

# ── ~/.engagement ─────────────────────────────────────────────────────────

if [[ -f "$HOME/.engagement" ]]; then
    rm -f "$HOME/.engagement"
    ok "removed ~/.engagement"
fi

# ── ~/.bashrc cleanup ─────────────────────────────────────────────────────

if [[ -f "$BASHRC" ]]; then
    cp "$BASHRC" "$BASHRC.repcollect-backup.$(date +%s)"
    ok "backed up ~/.bashrc to ~/.bashrc.repcollect-backup.*"

    # remove lines we added
    sed -i '/# repcollect/d' "$BASHRC"
    sed -i "\|$VENV_DIR/bin/activate|d" "$BASHRC"
    sed -i '\|pytools_venv/bin|d' "$BASHRC"
    sed -i '\|HOME/bin:\$PATH|d' "$BASHRC"
    sed -i '\|HOME/go/bin:\$PATH|d' "$BASHRC"
    sed -i '/DOTNET_ROOT/d' "$BASHRC"
    ok "cleaned ~/.bashrc"
fi

# ── engagements (optional) ────────────────────────────────────────────────

if [[ $WIPE_ENGAGEMENTS -eq 1 ]] && [[ -d "$HOME/engagements" ]]; then
    rm -rf "$HOME/engagements"
    ok "removed ~/engagements"
fi

echo ""
echo "══════════════════════════════════════════════"
echo " uninstall complete"
echo "══════════════════════════════════════════════"
echo " run: source ~/.bashrc   (or open a new shell)"
echo ""
