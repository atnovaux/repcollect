#!/usr/bin/env bash
# repkit install.sh — one-time setup for a Kali Linux engagement box

set -euo pipefail

REPKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_CONF="$REPKIT_DIR/tools.conf"
TOOLS_DIR="$HOME/tools"
BIN_DIR="$HOME/bin"
ZSHRC="$HOME/.zshrc"

add_to_zshrc() {
    # $1 = grep pattern (fixed-string); $2 = full line to append
    local pattern="$1" line="$2"
    if ! grep -qF "$pattern" "$ZSHRC" 2>/dev/null; then
        echo "$line" >> "$ZSHRC"
    fi
}

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
err()  { echo -e "${RED}[error]${NC} $*"; }
skip() { echo -e "        [skip]  $*"; }

FAILED_TOOLS=()
INSTALLED_TOOLS=()
SKIPPED_TOOLS=()
WARNED_TOOLS=()

# ── Step 1: Sanity checks ───────────────────────────────────────────────────

if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "error: repkit must be run with bash." >&2
    exit 1
fi


if [[ ! -f "$TOOLS_CONF" ]]; then
    err "tools.conf not found. run install.sh from the repkit/ directory."
    exit 1
fi

# ── Step 2: Check system dependencies ──────────────────────────────────────

echo "checking dependencies..."

for dep in apt git python3 pip3 curl; do
    if ! command -v "$dep" &>/dev/null; then
        err "$dep is required but not found."
        exit 1
    fi
done

HAS_GO=0
if command -v go &>/dev/null; then
    HAS_GO=1
else
    warn "go not found. skipping go-installed tools: httpx, gowitness, ffuf."
fi

HAS_DOTNET=0
if command -v dotnet &>/dev/null; then
    HAS_DOTNET=1
else
    echo "dotnet not found. installing..."
    if apt-cache show dotnet-sdk-9.0 &>/dev/null 2>&1 && sudo apt install -y dotnet-sdk-9.0; then
        HAS_DOTNET=1
        ok "dotnet-sdk-9.0 installed via apt"
    else
        echo "    apt install failed, trying Microsoft install script..."
        DOTNET_INSTALL_DIR="$HOME/.dotnet"
        curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 9.0 --install-dir "$DOTNET_INSTALL_DIR"
        if [[ -f "$DOTNET_INSTALL_DIR/dotnet" ]]; then
            export DOTNET_ROOT="$DOTNET_INSTALL_DIR"
            export PATH="$PATH:$DOTNET_INSTALL_DIR:$DOTNET_INSTALL_DIR/tools"
            add_to_zshrc 'DOTNET_ROOT' "export DOTNET_ROOT=\"$DOTNET_INSTALL_DIR\""
            add_to_zshrc 'DOTNET_ROOT:$DOTNET_ROOT/tools' 'export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"'
            ok "added dotnet to PATH in ~/.zshrc"
            HAS_DOTNET=1
            ok "dotnet installed via install script"
        else
            warn "dotnet install failed. TeamFiltration will be skipped."
        fi
    fi
fi

if ! grep -qF 'HOME/bin' "$ZSHRC" 2>/dev/null; then
    echo 'export PATH="$HOME/bin:$PATH"' >> "$ZSHRC"
    ok "added ~/bin to PATH in ~/.zshrc"
fi

# ── Step 3: Create directories + Python venv for tools ────────────────────

echo "creating directories..."
mkdir -p "$BIN_DIR"
mkdir -p "$HOME/engagements"
mkdir -p "$TOOLS_DIR"
ok "~/bin, ~/engagements, ~/tools ready"

PYTOOLS_VENV="$TOOLS_DIR/pytools_venv"
if [[ ! -d "$PYTOOLS_VENV" ]]; then
    echo "creating Python venv for tools..."
    python3 -m venv "$PYTOOLS_VENV"
    ok "tools venv created at $PYTOOLS_VENV"
else
    ok "tools venv already exists"
fi
VENV_PIP="$PYTOOLS_VENV/bin/pip"
"$VENV_PIP" install --upgrade pip -q

PYTOOLS_BIN="$PYTOOLS_VENV/bin"
if ! grep -qF "pytools_venv/bin" "$ZSHRC" 2>/dev/null; then
    echo "export PATH=\"$PYTOOLS_BIN:\$PATH\"" >> "$ZSHRC"
    ok "added $PYTOOLS_BIN to PATH in ~/.zshrc"
fi

# ── Step 4: Install tools from tools.conf ──────────────────────────────────

echo "installing tools..."

install_apt() {
    local pkg="$1"
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        skip "$pkg (already installed)"
        SKIPPED_TOOLS+=("$pkg")
    else
        if sudo apt install -y "$pkg"; then
            ok "$pkg"
            INSTALLED_TOOLS+=("$pkg")
        else
            err "failed to install $pkg"
            FAILED_TOOLS+=("$pkg")
        fi
    fi
}

install_git() {
    local url="$1"
    local repo_name
    repo_name=$(basename "$url" .git)
    local dest="$TOOLS_DIR/$repo_name"

    if [[ -d "$dest" ]]; then
        if git -C "$dest" pull --ff-only; then
            skip "$repo_name (already cloned, pulled latest)"
            SKIPPED_TOOLS+=("$repo_name")
        else
            warn "$repo_name: git pull failed, skipping"
            FAILED_TOOLS+=("$repo_name")
            return
        fi
    else
        if ! git clone "$url" "$dest"; then
            err "failed to clone $url"
            FAILED_TOOLS+=("$repo_name")
            return
        fi
    fi

    if [[ -f "$dest/go.mod" ]]; then
        if [[ $HAS_GO -eq 0 ]]; then
            warn "$repo_name: go not found, skipping build"
            WARNED_TOOLS+=("$repo_name(no-go)")
        else
            echo "    building $repo_name (go install)..."
            if (cd "$dest" && go install ./...); then
                ok "$repo_name (built)"
            else
                err "$repo_name: go install failed"
                FAILED_TOOLS+=("$repo_name")
                return
            fi
        fi
    elif [[ -f "$dest/setup.py" ]] || [[ -f "$dest/pyproject.toml" ]]; then
        "$VENV_PIP" install -e "$dest" || { warn "$repo_name: pip install -e failed"; WARNED_TOOLS+=("$repo_name(pip)"); }
    elif [[ -f "$dest/requirements.txt" ]]; then
        "$VENV_PIP" install -r "$dest/requirements.txt" || { warn "$repo_name: pip requirements install failed"; WARNED_TOOLS+=("$repo_name(pip)"); }
    elif [[ -f "$dest/Makefile" ]]; then
        make -C "$dest" || { warn "$repo_name: make failed"; WARNED_TOOLS+=("$repo_name(make)"); }
    fi

    if [[ "$repo_name" == "TeamFiltration" ]] && [[ $HAS_DOTNET -eq 1 ]]; then
        local tf_proj="$dest/TeamFiltration"
        if [[ -d "$tf_proj" ]]; then
            echo "    building TeamFiltration (this may take a moment)..."
            if dotnet publish "$tf_proj" -c Release -r linux-x64 --self-contained true; then
                ok "TeamFiltration (built)"
                INSTALLED_TOOLS+=("TeamFiltration")
            else
                err "TeamFiltration: dotnet publish failed"
                FAILED_TOOLS+=("TeamFiltration")
            fi
            return
        fi
    fi

    ok "$repo_name"
    INSTALLED_TOOLS+=("$repo_name")
}

install_pip() {
    local pkg="$1"
    if "$VENV_PIP" install --upgrade "$pkg"; then
        ok "$pkg"
        INSTALLED_TOOLS+=("$pkg")
    else
        err "failed to install pip package: $pkg"
        FAILED_TOOLS+=("$pkg")
    fi
}

install_go() {
    local module="$1"
    if [[ $HAS_GO -eq 0 ]]; then
        skip "$module (go not available)"
        SKIPPED_TOOLS+=("$module")
        return
    fi

    if go install "${module}@latest"; then
        ok "$module"
        INSTALLED_TOOLS+=("$module")

        # ensure ~/go/bin is in PATH
        if ! grep -qF 'HOME/go/bin' "$ZSHRC" 2>/dev/null; then
            echo 'export PATH="$HOME/go/bin:$PATH"' >> "$ZSHRC"
            ok "added ~/go/bin to PATH in ~/.zshrc"
        fi
    else
        err "failed to install go module: $module"
        FAILED_TOOLS+=("$module")
    fi
}

while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    method="${line%%:*}"
    value="${line#*:}"

    case "$method" in
        apt)   install_apt "$value" ;;
        git)   install_git "$value" ;;
        pip)   install_pip "$value" ;;
        go)    install_go "$value" ;;
        manual) warn "manual install required: $value" ;;
        *)     warn "unknown install method '$method' for: $value" ;;
    esac
done < "$TOOLS_CONF"

# ── Step 5: Symlink wrappers ────────────────────────────────────────────────

echo "symlinking wrappers..."
for wrapper in "$REPKIT_DIR/wrappers/"*; do
    [[ -f "$wrapper" ]] || continue
    chmod +x "$wrapper"
    ln -sf "$wrapper" "$BIN_DIR/$(basename "$wrapper")"
    ok "~/bin/$(basename "$wrapper") -> $wrapper"
done

# ── Step 6: Summary ─────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════"
echo " repkit install summary"
echo "══════════════════════════════════════════════"
if [[ ${#INSTALLED_TOOLS[@]} -gt 0 ]]; then
    echo -e "${GREEN} installed${NC}"
    for t in "${INSTALLED_TOOLS[@]}"; do echo "   + $t"; done
fi
if [[ ${#SKIPPED_TOOLS[@]} -gt 0 ]]; then
    echo " skipped (already present)"
    for t in "${SKIPPED_TOOLS[@]}"; do echo "   = $t"; done
fi
if [[ ${#WARNED_TOOLS[@]} -gt 0 ]]; then
    echo -e "${YELLOW} warnings${NC}"
    for t in "${WARNED_TOOLS[@]}"; do echo "   ! $t"; done
fi
if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
    echo -e "${RED} failed${NC}"
    for t in "${FAILED_TOOLS[@]}"; do echo "   x $t"; done
fi
echo ""
