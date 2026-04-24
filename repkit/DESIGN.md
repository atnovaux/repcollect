# repkit Design Document

**Version:** 1.0  
**Date:** 2026-04-24  
**Author:** Thomas Kang  
**Status:** Draft

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [Scope and Non-Goals](#2-scope-and-non-goals)
3. [Repository Structure](#3-repository-structure)
4. [State Management](#4-state-management)
5. [install.sh Specification](#5-installsh-specification)
6. [tools.conf Format and Tool List](#6-toolsconf-format-and-tool-list)
7. [lib/engagement.sh Shared Library](#7-libengagementsh-shared-library)
8. [Wrapper Pattern](#8-wrapper-pattern)
9. [Per-Tool Wrapper Specifications](#9-per-tool-wrapper-specifications)
10. [Error Cases](#10-error-cases)
11. [Implementation Order](#11-implementation-order)

---

## 1. Purpose

repkit is a one-time setup tool for Kali Linux engagement boxes used in red team operations. Its single job is to guarantee that every tool on the box writes output into a predictable, consistent directory structure organized by engagement target. This eliminates the common problem of assessment artifacts being scattered across home directories, `/tmp`, working directories, or wherever the operator happened to be when they ran a tool.

repkit does not run tools itself. It installs tools and then wraps them: every tool the operator calls is intercepted by a thin bash wrapper that resolves the active engagement, creates the correct output directory, and invokes the real tool with output flags hard-coded to that directory. The operator does not choose where output goes — the wrapper decides. This is intentional and non-negotiable by design.

The engagement lifecycle (create, switch, list) is managed by `rpt` — see the repcollect top-level documentation. repkit only installs tools and the shared `lib/engagement.sh` that wrappers source; it does not ship its own engagement CLI.

---

## 2. Scope and Non-Goals

**In scope:**

- Installing a fixed set of red team tools on a Kali Linux box via `install.sh`
- Wrapping each installed tool so output is forced to `~/engagements/<target>/<tool>/`
- Providing `lib/engagement.sh` helpers that wrappers use to resolve the active engagement and output directory

**Out of scope:**

- Tool configuration (e.g., wordlists, API keys, Burp extensions) — repkit does not manage tool configuration, only tool output location
- Multi-target parallelism — one active engagement at a time
- Remote output (e.g., writing to S3 or a shared NFS mount)
- Reporting or artifact aggregation — that is repcollect's job
- Windows or macOS support — Kali Linux only
- Running as root by design — install.sh uses sudo where needed, and wrappers run as the operator user

---

## 3. Repository Structure

All repkit files live under `repcollect/repkit/` in the repcollect monorepo:

```
repkit/
├── install.sh              # one-time setup script
├── tools.conf              # tool list with install methods
├── wrappers/               # one bash script per tool
│   ├── canvass
│   ├── trufflehog
│   ├── cloud-enum
│   ├── roadtools
│   ├── s3scanner
│   ├── nmap
│   ├── httpx
│   ├── gowitness
│   ├── teamfiltration
│   ├── dig
│   └── ffuf
└── lib/
    └── engagement.sh       # shared bash library
```

After `install.sh` runs, the operator's home directory has:

```
~/bin/
│   # symlinks to every file in repkit/wrappers/
│   ├── canvass -> .../repkit/wrappers/canvass
│   ├── trufflehog -> .../repkit/wrappers/trufflehog
│   ├── cloud-enum -> .../repkit/wrappers/cloud-enum
│   ├── roadtools -> .../repkit/wrappers/roadtools
│   ├── s3scanner -> .../repkit/wrappers/s3scanner
│   ├── nmap -> .../repkit/wrappers/nmap
│   ├── httpx -> .../repkit/wrappers/httpx
│   ├── gowitness -> .../repkit/wrappers/gowitness
│   ├── teamfiltration -> .../repkit/wrappers/teamfiltration
│   ├── dig -> .../repkit/wrappers/dig
│   └── ffuf -> .../repkit/wrappers/ffuf

~/.engagement                # active target, written by rpt
~/engagements/
└── <target>/               # created by rpt new
    └── ext/                # created by rpt run -t ext or ensure_engagement_dir when ENGAGEMENT_TYPE=ext
        ├── recon/
        ├── trufflehog/
        ├── cloud/
        ├── roadtools/
        ├── s3scanner/
        ├── nmap/
        ├── httpx/
        ├── gowitness/
        ├── spray/
        ├── dns/
        └── ffuf/
```

> **Note:** Type subdirectories (ext/, int/) are created on demand by ensure_engagement_dir() when ENGAGEMENT_TYPE is set. rpt new does not pre-create them.

---

## 4. State Management

### 4.1 The `~/.engagement` File

The active engagement is a single line of text in `~/.engagement`. The file contains only the target domain string (e.g., `example.com`) with no trailing whitespace or newline beyond what echo writes. There is no JSON, no YAML, no additional metadata.

**Location:** `$HOME/.engagement`  
**Format:** A single line containing the target name as passed to `rpt new` or `rpt use`. The target name is also the directory name under `~/engagements/`.  
**Permissions:** Readable and writable by the operator user only (`chmod 600`).

The file is created or overwritten by `rpt new` and `rpt use`. It is read at wrapper runtime by `lib/engagement.sh`. It is deleted by nothing — the operator removes it manually or switches with `rpt use`.

### 4.2 Target Name Constraints

Target names must be filesystem-safe directory names. The `rpt new` and `rpt use` commands enforce:

- No leading or trailing whitespace
- No path separators (`/`)
- No null bytes
- Recommended convention: lowercase domain name (e.g., `example.com`, `internal.corp`)

### 4.3 `ENGAGEMENT_TYPE` Environment Variable

The active engagement type (e.g., `ext`, `int`) is communicated to wrappers via the `ENGAGEMENT_TYPE` environment variable. This variable is set by `rpt run` before invoking each tool and is read by `ensure_engagement_dir()` to determine the output path.

When `ENGAGEMENT_TYPE` is set, output goes to:
```
~/engagements/<target>/<type>/<tool_subdir>/
```

When `ENGAGEMENT_TYPE` is unset (standalone wrapper usage), output goes to:
```
~/engagements/<target>/<tool_subdir>/
```

Valid values for v1.0: `ext` (external assessment). `int` (internal) is reserved for future use.

Wrappers do not set or validate `ENGAGEMENT_TYPE` — they only read it. `rpt run` is responsible for setting it.

---

## 5. install.sh Specification

### 5.1 Overview

`install.sh` is a bash script located at `repkit/install.sh`. It is safe to run multiple times (idempotent). It does not require root to run, but will invoke `sudo` for `apt install` calls. It must be run by the operator user (not root directly) so that symlinks and the engagements directory are created under the correct home directory.

### 5.2 Execution Steps

The script executes the following steps in order:

**Step 1: Sanity checks**

- Verify the shell is bash (fail if `$BASH_VERSION` is unset).
- Verify the script is not being run as root directly (fail if `$EUID -eq 0`). Print a message telling the operator to run as their user account.
- Verify `~/bin` is in `$PATH`. If it is not, print a warning and instructions for adding it (e.g., `export PATH="$HOME/bin:$PATH"` in `~/.zshrc`). Do not fail; continue.

**Step 2: Verify system dependencies**

Check that the following are available before proceeding. These are not installed by repkit — they are expected to be present on Kali Linux:

- `apt` (package manager)
- `git`
- `python3`
- `pip3`
- `curl`
- `go` (for tools that require a Go build; print a specific warning if missing but do not fail the whole install)

For each missing dependency (except `go`), print an error and exit.

**Step 3: Create `~/bin` and `~/engagements`**

```bash
mkdir -p "$HOME/bin"
mkdir -p "$HOME/engagements"
```

Both `mkdir -p` calls are idempotent.

**Step 4: Read and process `tools.conf`**

Parse `tools.conf` line by line. Skip lines that are blank or start with `#`. For each line, extract the install method and the install target. Execute the install action for that method (see Section 5.3). If any install step fails, print an error message identifying the tool and continue with the remaining tools rather than aborting the entire install.

**Step 5: Symlink wrappers**

For every file in `repkit/wrappers/`:

```bash
ln -sf "$(realpath repkit/wrappers/<tool>)" "$HOME/bin/<tool>"
```

Using `ln -sf` makes this idempotent. The symlink is overwritten if it already exists.

After symlinking, `chmod +x` every wrapper file to ensure it is executable.

**Step 6: Print completion summary**

Print a summary of what was installed, what was skipped (already present), and what failed. End with instructions reminding the operator to:

1. Ensure `~/bin` is in `$PATH`
2. Run `rpt new <target>` to create their first engagement
3. Run `rpt use <target>` to set the active engagement

### 5.3 Install Methods

**`apt:<package>`**

```bash
if ! dpkg -l <package> &>/dev/null; then
    sudo apt install -y <package>
else
    echo "[skip] <package> already installed"
fi
```

**`git:<url>`**

Clones into `~/tools/<repo-name>/`. The repo name is derived from the last path segment of the URL, stripping `.git`. If the directory already exists, runs `git pull` instead of cloning.

```bash
REPO_NAME=$(basename <url> .git)
if [ ! -d "$HOME/tools/$REPO_NAME" ]; then
    git clone <url> "$HOME/tools/$REPO_NAME"
else
    git -C "$HOME/tools/$REPO_NAME" pull
fi
```

After cloning, if a `Makefile` is present, runs `make`. If `setup.py` is present, runs `pip3 install -e .`. If `requirements.txt` is present, runs `pip3 install -r requirements.txt`. These build steps run unconditionally on each install (idempotent for pip).

**`pip:<package>`**

```bash
pip3 install --upgrade <package>
```

Using `--upgrade` is idempotent.

**`go:<module-path>`**

```bash
go install <module-path>@latest
```

Requires `go` in PATH. If `go` is not available, skip and print an error. The installed binary ends up in `$GOPATH/bin` or `$HOME/go/bin`. install.sh adds `$HOME/go/bin` to PATH in `~/.zshrc` if it is not already present.

**`manual:<description>`**

Print a human-readable message telling the operator to install this tool manually. Include the description. Skip the tool in the automated steps.

### 5.4 Idempotency Guarantees

Every action in install.sh must be safe to run a second time without causing errors or duplicate side effects:

- `mkdir -p` does not fail if the directory exists.
- `ln -sf` overwrites existing symlinks.
- `apt install -y` is idempotent (apt skips already-installed packages).
- `pip3 install --upgrade` upgrades if needed, does nothing if already current.
- `git clone` is replaced by `git pull` when the directory exists.
- `go install @latest` is idempotent.

### 5.5 Error Cases

| Condition | Behavior |
|---|---|
| `apt` not found | Exit 1: "error: apt not found. repkit requires a Debian-based system." |
| `git` not found | Exit 1: "error: git is required." |
| `python3` not found | Exit 1: "error: python3 is required." |
| `pip3` not found | Exit 1: "error: pip3 is required." |
| `go` not found | Warning only; skip go-installed tools. |
| `tools.conf` not found | Exit 1: "error: tools.conf not found. run install.sh from the repkit/ directory." |
| Individual tool install fails | Print error, continue with remaining tools. |
| Wrapper file not executable | `chmod +x` it. |

---

## 6. tools.conf Format and Tool List

### 6.1 Format

`tools.conf` is a plain text file. One entry per line. Blank lines and lines beginning with `#` are ignored. Each entry has the format:

```
<method>:<value>
```

Where `<method>` is one of: `apt`, `git`, `pip`, `go`, `manual`.

### 6.2 Complete Tool List

```
# repkit tools.conf
# format: <method>:<value>

# ── Recon / OSINT ──────────────────────────────────────────────────────
# canvass: cloned from https://github.com/atnovaux/canvass.git
git:https://github.com/atnovaux/canvass.git

# TruffleHog: secrets scanner
pip:trufflehog

# ── Cloud / Identity ────────────────────────────────────────────────────
# cloud_enum: multi-cloud OSINT enumeration
git:https://github.com/initstring/cloud_enum

# ROADtools: Azure AD enumeration suite
pip:roadtools

# S3Scanner: unauthenticated S3 bucket scanner
pip:s3scanner

# ── Active Scanning ─────────────────────────────────────────────────────
# nmap: network mapper (standard Kali package)
apt:nmap

# httpx: fast HTTP probe
go:github.com/projectdiscovery/httpx/cmd/httpx

# gowitness: web screenshot tool
go:github.com/sensepost/gowitness

# ── User Enum & Password Spray ──────────────────────────────────────────
# TeamFiltration: O365 user enumeration and spray
git:https://github.com/Flangvik/TeamFiltration

# ── DNS / Email ─────────────────────────────────────────────────────────
# dig: DNS lookup utility (part of bind9-dnsutils on Kali)
apt:bind9-dnsutils

# ── Web Discovery ───────────────────────────────────────────────────────
# ffuf: fast web fuzzer written in Go
go:github.com/ffuf/ffuf/v2
```

### 6.3 Tool Install Method Rationale

| Tool | Method | Rationale |
|---|---|---|
| canvass | git | Cloned from https://github.com/atnovaux/canvass.git; installed via pip install -e after clone |
| TruffleHog | pip | Official distribution via PyPI (`trufflehog` package) |
| cloud_enum | git | No PyPI package; installed from GitHub with `pip install -r requirements.txt` |
| ROADtools | pip | Official PyPI package (`roadtools`); installs `roadrecon` and `roadtx` CLI |
| S3Scanner | pip | PyPI package (`s3scanner`) |
| Nmap | apt | Standard Kali package; always present but pinned for explicitness |
| httpx | go | Official distribution via `go install`; projectdiscovery does not publish apt packages |
| gowitness | go | Official distribution via `go install`; no apt package |
| TeamFiltration | git | .NET tool; `git clone` + build via `dotnet publish` — see wrapper spec for binary path |
| dig | apt | Part of `bind9-dnsutils`; present on Kali but explicit for documentation |
| ffuf | go | Official distribution via `go install`; fastest way to get the latest version |

---

## 7. lib/engagement.sh Shared Library

All wrappers source `lib/engagement.sh` at startup. This library provides two functions used by every wrapper.

### 7.1 Location and Sourcing

The library is at `repkit/lib/engagement.sh`. Wrappers source it using the path relative to the wrapper's own location:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"
```

Because wrappers are symlinked to `~/bin/`, `${BASH_SOURCE[0]}` resolves the symlink back to the actual wrapper file location using `readlink -f` or by following the symlink in the source step. The sourcing pattern must resolve to the actual repkit directory, not `~/bin/`. Implementation:

```bash
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"
```

### 7.2 Function: `get_active_engagement()`

Returns the active engagement target string by printing it to stdout.

**Logic:**

1. If `~/.engagement` exists and is non-empty, read the first line, strip whitespace, print it, and return 0.
2. Else print to stderr: `error: no active engagement. run 'rpt use <target>' first.` and return 1.

**Usage in wrappers:**

```bash
TARGET=$(get_active_engagement) || exit 1
```

### 7.3 Function: `ensure_engagement_dir()`

**Signature:** `ensure_engagement_dir <tool_subdir>`

Creates the output directory for the active engagement, type (if set), and tool. Returns the absolute path.

**Logic:**

1. Call `get_active_engagement()` to get `$TARGET`. Exit 1 on failure.
2. If `$ENGAGEMENT_TYPE` is set and non-empty, compute `OUTPUT_DIR="$HOME/engagements/$TARGET/$ENGAGEMENT_TYPE/$1"`.
3. Else compute `OUTPUT_DIR="$HOME/engagements/$TARGET/$1"`.
4. If `$OUTPUT_DIR` does not exist, `mkdir -p "$OUTPUT_DIR"`.
5. If `mkdir` fails, print to stderr and return 1.
6. Print `$OUTPUT_DIR` to stdout and return 0.

**Usage in wrappers:**

```bash
OUTPUT_DIR=$(ensure_engagement_dir nmap) || exit 1
```

### 7.4 Complete engagement.sh

```bash
#!/usr/bin/env bash
# lib/engagement.sh — shared engagement state functions for repkit wrappers

get_active_engagement() {
    local state_file="$HOME/.engagement"
    if [[ -f "$state_file" ]]; then
        local target
        target=$(tr -d '[:space:]' < "$state_file")
        if [[ -n "$target" ]]; then
            printf '%s' "$target"
            return 0
        fi
    fi

    echo "error: no active engagement. run 'rpt use <target>' first." >&2
    return 1
}

ensure_engagement_dir() {
    local tool_subdir="$1"
    local target
    target=$(get_active_engagement) || return 1

    local output_dir
    if [[ -n "${ENGAGEMENT_TYPE:-}" ]]; then
        output_dir="$HOME/engagements/$target/$ENGAGEMENT_TYPE/$tool_subdir"
    else
        output_dir="$HOME/engagements/$target/$tool_subdir"
    fi

    if [[ ! -d "$output_dir" ]]; then
        mkdir -p "$output_dir" || {
            echo "error: could not create output directory $output_dir" >&2
            return 1
        }
    fi

    printf '%s' "$output_dir"
    return 0
}
```

---

## 8. Wrapper Pattern

### 8.1 What a Wrapper Does

Each wrapper in `repkit/wrappers/` is a bash script that:

1. Sources `lib/engagement.sh`.
2. Resolves the active engagement and output directory.
3. Invokes the real tool binary with output flags hard-coded to point into the engagement directory.
4. Passes all operator-supplied arguments through to the real tool, except arguments that conflict with output location flags (those are stripped or ignored — see per-tool notes).
5. Exits with the real tool's exit code.

### 8.2 What a Wrapper Does NOT Do

- Wrappers do not allow the operator to override the output directory. Flags like `-o`, `-oA`, `--output` passed by the operator that conflict with the wrapper's output flags are silently dropped (filtered from `$@`) or the wrapper invokes the tool in a way that makes them irrelevant. Each wrapper documents its specific behavior.
- Wrappers do not manage engagement lifecycle. They do not call `rpt new` or write to `~/.engagement`.
- Wrappers do not parse tool output or transform results. Raw tool output goes into the engagement directory; repcollect handles parsing.

### 8.3 Argument Passthrough

Wrappers pass `$@` to the real tool after inserting the output flags. For tools where the operator can accidentally supply a conflicting output flag, the wrapper filters it out using a simple loop. The filter must be conservative — it only removes the specific output flag for that tool, not arbitrary arguments.

### 8.4 Real Tool Binary Path

Each wrapper invokes the real tool by its canonical binary name, with the exception of tools whose real binary is shadowed by the wrapper itself (e.g., `nmap` and `dig`). For those tools, the wrapper uses the full path to the real binary:

- `/usr/bin/nmap` (not `nmap`, which would invoke the wrapper again)
- `/usr/bin/dig` (not `dig`)

For all other tools installed via `go install`, `pip`, or `git`, the wrapper calls the binary by name since those binaries are in `$GOPATH/bin`, the pip bin directory, or `~/tools/`, not in `~/bin/`.

### 8.5 Example Wrapper (nmap)

See Section 10.5 for the full nmap wrapper. This serves as the canonical example.

### 8.6 Wrapper Template

```bash
#!/usr/bin/env bash
# wrappers/<tool> — repkit wrapper for <tool>
# forces output to ~/engagements/<active-target>/<subdir>/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir <subdir>) || exit 1

# <tool-specific output flag> "$OUTPUT_DIR/<filename-or-pattern>"
exec /path/to/real/<tool> \
    <output-flag> "$OUTPUT_DIR/<output-file>" \
    "$@"
```

---

## 9. Per-Tool Wrapper Specifications

### 9.1 canvass

**Tool description:** Internal OSINT collection tool from the repcollect project. Accepts a target domain and writes JSON output to a specified path.

**Real binary:** `canvass` (Installed from https://github.com/atnovaux/canvass.git via git clone into ~/tools/canvass/; pip install -e ~/tools/canvass/ adds the canvass binary to PATH.)

**Engagement subdirectory:** `recon/`

**Output mechanism:** canvass accepts `--output <file>` to write JSON results. The wrapper forces this flag to `$OUTPUT_DIR/canvass.json`.

**Conflicting flag handling:** If the operator passes `--output` or `-o`, the wrapper strips those arguments (and their values) before constructing the exec call.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/canvass — repkit wrapper for canvass

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir recon) || exit 1

# Strip any --output/-o flags supplied by the operator
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then
        skip_next=0
        continue
    fi
    if [[ "$arg" == "--output" || "$arg" == "-o" ]]; then
        skip_next=1
        continue
    fi
    ARGS+=("$arg")
done

exec canvass --output "$OUTPUT_DIR/canvass.json" "${ARGS[@]}"
```

**Output files written:** `~/engagements/<target>/recon/canvass.json`

---

### 9.2 trufflehog

**Tool description:** Scans git repositories, filesystems, and other sources for secrets and credentials. Distributed via pip as `trufflehog`.

**Real binary:** `trufflehog` (pip-installed; available on PATH after pip install)

**Engagement subdirectory:** `trufflehog/`

**Output mechanism:** TruffleHog writes results to stdout by default. It supports `--json` for machine-readable output. The wrapper runs trufflehog with `--json` and redirects stdout to a file. Stderr (progress, errors) still prints to the terminal.

TruffleHog does not have a native `--output <file>` flag in the CLI (output is always to stdout). The wrapper uses shell redirection.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/trufflehog — repkit wrapper for trufflehog

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir trufflehog) || exit 1
OUTFILE="$OUTPUT_DIR/trufflehog.json"

echo "[repkit] trufflehog output -> $OUTFILE" >&2

exec trufflehog --json "$@" > "$OUTFILE"
```

Note: `exec` with stdout redirection requires care — this wrapper does not use `exec` with the redirect directly (not portable). Instead it uses:

```bash
trufflehog --json "$@" > "$OUTFILE"
exit $?
```

**Output files written:** `~/engagements/<target>/trufflehog/trufflehog.json`

**Note:** Multiple runs append collisions in filename. The wrapper uses a timestamped filename to avoid overwriting:

```bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="$OUTPUT_DIR/trufflehog_${TIMESTAMP}.json"
```

This pattern (timestamp suffix) is used for all tools that write a single output file and may be run multiple times per engagement. Tools like nmap that use `-oA` with a basename benefit from the same pattern.

---

### 9.3 cloud-enum

**Tool description:** `cloud_enum` by initstring. Enumerates cloud resources across AWS, Azure, and GCP using keyword-based DNS and HTTP checks.

**Real binary:** `cloud_enum.py` located at `~/tools/cloud_enum/cloud_enum.py` (git clone; no `pip install` entry point). The wrapper calls the script directly via Python.

**Engagement subdirectory:** `cloud/`

**Output mechanism:** cloud_enum supports:
- `-l <file>` or `--logfile <file>`: writes a plain-text log to a file
- `-m <modules>`: optional module selection

The wrapper forces `-l "$OUTPUT_DIR/cloud_enum_<timestamp>.txt"`. cloud_enum does not support JSON output natively; the log file is the primary artifact.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/cloud-enum — repkit wrapper for cloud_enum

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir cloud) || exit 1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="$OUTPUT_DIR/cloud_enum_${TIMESTAMP}.txt"

CLOUD_ENUM="$HOME/tools/cloud_enum/cloud_enum.py"
if [[ ! -f "$CLOUD_ENUM" ]]; then
    echo "error: cloud_enum not found at $CLOUD_ENUM. run install.sh." >&2
    exit 1
fi

# Strip -l/--logfile flags from operator args
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
    if [[ "$arg" == "-l" || "$arg" == "--logfile" ]]; then skip_next=1; continue; fi
    ARGS+=("$arg")
done

echo "[repkit] cloud-enum output -> $OUTFILE" >&2
python3 "$CLOUD_ENUM" -l "$OUTFILE" "${ARGS[@]}"
exit $?
```

**Output files written:** `~/engagements/<target>/cloud/cloud_enum_<timestamp>.txt`

---

### 9.4 roadtools

**Tool description:** ROADtools is an Azure Active Directory enumeration suite by Dirk-jan Mollema. The primary CLI commands are `roadrecon` (data collection) and `roadtx` (token acquisition).

**Real binary:** `roadrecon` and `roadtx` (pip-installed; both are on PATH after `pip install roadtools`)

**Engagement subdirectory:** `roadtools/`

**Output mechanism:** `roadrecon gather` writes to a local SQLite database. The database path is set with `-d <file>` or `--database <file>`. Default is `roadrecon.db` in the current working directory.

The wrapper changes into `$OUTPUT_DIR` before running `roadrecon`, so the default database is written there. It also explicitly passes `-d "$OUTPUT_DIR/roadrecon.db"` to `roadrecon gather` subcommands.

For `roadtx` tokens and `roadrecon auth`, output is stdout/tokens file; the wrapper creates a timestamped subdirectory under `$OUTPUT_DIR` for each run to avoid collision.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/roadtools — repkit wrapper for roadrecon/roadtx

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir roadtools) || exit 1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUTPUT_DIR/run_${TIMESTAMP}"
mkdir -p "$RUN_DIR"

# Determine which roadtools command the operator is invoking
SUBCMD="${1:-}"

case "$SUBCMD" in
    roadrecon)
        shift
        # Inject -d for gather subcommand
        if [[ "${1:-}" == "gather" ]]; then
            shift
            ARGS=()
            skip_next=0
            for arg in "$@"; do
                if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
                if [[ "$arg" == "-d" || "$arg" == "--database" ]]; then skip_next=1; continue; fi
                ARGS+=("$arg")
            done
            echo "[repkit] roadrecon output -> $RUN_DIR/roadrecon.db" >&2
            roadrecon gather -d "$RUN_DIR/roadrecon.db" "${ARGS[@]}"
        else
            roadrecon "$@"
        fi
        ;;
    roadtx)
        shift
        echo "[repkit] roadtx run dir -> $RUN_DIR" >&2
        cd "$RUN_DIR"
        roadtx "$@"
        ;;
    *)
        echo "[repkit] usage: roadtools <roadrecon|roadtx> [args...]" >&2
        exit 1
        ;;
esac
exit $?
```

**Output files written:** `~/engagements/<target>/roadtools/run_<timestamp>/roadrecon.db` (and roadtx artifacts in the same run directory)

---

### 9.5 s3scanner

**Tool description:** S3Scanner by sa7mon. Scans for open, misconfigured, or listable S3 buckets. Distributed via pip as `s3scanner`.

**Real binary:** `s3scanner` (pip-installed)

**Engagement subdirectory:** `s3scanner/`

**Output mechanism:** s3scanner supports `--out-file <file>` to write results to a file (one bucket per line with status). It also supports `--json` to write JSON output. The wrapper uses `--out-file "$OUTPUT_DIR/s3scanner_<timestamp>.txt"`.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/s3scanner — repkit wrapper for s3scanner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir s3scanner) || exit 1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="$OUTPUT_DIR/s3scanner_${TIMESTAMP}.txt"

# Strip --out-file flags
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
    if [[ "$arg" == "--out-file" ]]; then skip_next=1; continue; fi
    ARGS+=("$arg")
done

echo "[repkit] s3scanner output -> $OUTFILE" >&2
s3scanner --out-file "$OUTFILE" "${ARGS[@]}"
exit $?
```

**Output files written:** `~/engagements/<target>/s3scanner/s3scanner_<timestamp>.txt`

---

### 9.6 nmap

**Tool description:** Network mapper. The canonical Kali Linux network scanner.

**Real binary:** `/usr/bin/nmap` (full path used to avoid self-invocation since the wrapper is named `nmap` and shadows the system binary in `~/bin/`)

**Engagement subdirectory:** `nmap/`

**Output mechanism:** nmap supports `-oA <basename>` which writes three output files simultaneously:
- `<basename>.nmap` — normal (human-readable) output
- `<basename>.xml` — XML output
- `<basename>.gnmap` — grepable output

The wrapper forces `-oA "$OUTPUT_DIR/nmap_<timestamp>"`. This gives all three formats in one invocation.

**Conflicting flag handling:** The wrapper strips `-oA`, `-oN`, `-oX`, `-oG`, `-oS` and their values from operator-supplied arguments before appending the forced `-oA`.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/nmap — repkit wrapper for nmap
# forces -oA output to the active engagement nmap directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir nmap) || exit 1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASENAME="$OUTPUT_DIR/nmap_${TIMESTAMP}"

# Strip output flags from operator args
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
    case "$arg" in
        -oA|-oN|-oX|-oG|-oS)
            skip_next=1
            continue
            ;;
    esac
    ARGS+=("$arg")
done

echo "[repkit] nmap output -> ${BASENAME}.{nmap,xml,gnmap}" >&2
exec /usr/bin/nmap -oA "$BASENAME" "${ARGS[@]}"
```

**Output files written:**
- `~/engagements/<target>/nmap/nmap_<timestamp>.nmap`
- `~/engagements/<target>/nmap/nmap_<timestamp>.xml`
- `~/engagements/<target>/nmap/nmap_<timestamp>.gnmap`

---

### 9.7 httpx

**Tool description:** Fast HTTP probe by ProjectDiscovery. Accepts a list of hosts/URLs and probes them for live HTTP services.

**Real binary:** `httpx` (go-installed; in `$GOPATH/bin` or `$HOME/go/bin`)

**Engagement subdirectory:** `httpx/`

**Output mechanism:** httpx supports:
- `-o <file>` or `-output <file>`: write output to a file (one result per line)
- `-json`: output in JSON format (use with `-o` for JSON file)

The wrapper forces `-o "$OUTPUT_DIR/httpx_<timestamp>.json"` and `-json` for structured output. If the operator passes `-o` or `-output`, those are stripped.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/httpx — repkit wrapper for httpx

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir httpx) || exit 1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="$OUTPUT_DIR/httpx_${TIMESTAMP}.json"

# Strip -o/-output flags
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
    if [[ "$arg" == "-o" || "$arg" == "-output" ]]; then skip_next=1; continue; fi
    ARGS+=("$arg")
done

echo "[repkit] httpx output -> $OUTFILE" >&2
httpx -json -o "$OUTFILE" "${ARGS[@]}"
exit $?
```

**Output files written:** `~/engagements/<target>/httpx/httpx_<timestamp>.json`

---

### 9.8 gowitness

**Tool description:** Web screenshot tool by sensepost. Takes screenshots of URLs using a headless Chrome/Chromium browser.

**Real binary:** `gowitness` (go-installed)

**Engagement subdirectory:** `gowitness/`

**Output mechanism:** gowitness stores screenshots and a sqlite database. The output directory is set with `--screenshot-path <dir>` (or `--destination` in older versions). The database path is `--db-path <file>`.

The wrapper forces:
- `--screenshot-path "$OUTPUT_DIR/screenshots/"`
- `--db-path "$OUTPUT_DIR/gowitness.sqlite3"`

**Conflicting flag handling:** Strip `--screenshot-path`, `--destination`, `--db-path` and their values.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/gowitness — repkit wrapper for gowitness

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir gowitness) || exit 1
mkdir -p "$OUTPUT_DIR/screenshots"

# Strip output-related flags
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
    case "$arg" in
        --screenshot-path|--destination|--db-path)
            skip_next=1; continue ;;
    esac
    ARGS+=("$arg")
done

echo "[repkit] gowitness output -> $OUTPUT_DIR/" >&2
gowitness \
    --screenshot-path "$OUTPUT_DIR/screenshots/" \
    --db-path "$OUTPUT_DIR/gowitness.sqlite3" \
    "${ARGS[@]}"
exit $?
```

**Output files written:**
- `~/engagements/<target>/gowitness/screenshots/<url-hash>.png` (one per screenshotted URL)
- `~/engagements/<target>/gowitness/gowitness.sqlite3`

---

### 9.9 teamfiltration

**Tool description:** TeamFiltration by Flangvik. Enumerates and sprays Microsoft 365 / Azure AD accounts via Teams, SharePoint, and OneDrive endpoints.

**Real binary:** TeamFiltration is a .NET 6 application compiled from source. After `git clone` and `dotnet publish`, the binary is at `~/tools/TeamFiltration/TeamFiltration/bin/Release/net6.0/linux-x64/publish/TeamFiltration`. install.sh builds this binary and symlinks it to `~/bin/TeamFiltration-bin` (to avoid shadowing the wrapper).

**Engagement subdirectory:** `spray/`

**Output mechanism:** TeamFiltration writes all output to a directory specified with `--outdir <dir>`. It creates subdirectories within that directory for each module (e.g., `--enum`, `--spray`, `--exfil`). The wrapper forces `--outdir "$OUTPUT_DIR"`.

**Conflicting flag handling:** Strip `--outdir` and its value.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/teamfiltration — repkit wrapper for TeamFiltration

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir spray) || exit 1

TF_BIN="$HOME/tools/TeamFiltration/TeamFiltration/bin/Release/net6.0/linux-x64/publish/TeamFiltration"
if [[ ! -f "$TF_BIN" ]]; then
    echo "error: TeamFiltration binary not found at $TF_BIN. run install.sh to build it." >&2
    exit 1
fi

# Strip --outdir flag
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
    if [[ "$arg" == "--outdir" ]]; then skip_next=1; continue; fi
    ARGS+=("$arg")
done

echo "[repkit] teamfiltration output -> $OUTPUT_DIR/" >&2
"$TF_BIN" --outdir "$OUTPUT_DIR" "${ARGS[@]}"
exit $?
```

**Output files written:** `~/engagements/<target>/spray/` (TeamFiltration creates its own subdirectory structure within this directory)

**Note on install.sh:** For TeamFiltration, `tools.conf` uses `git:https://github.com/Flangvik/TeamFiltration`. After cloning, install.sh runs:

```bash
cd ~/tools/TeamFiltration/TeamFiltration
dotnet publish -c Release -r linux-x64 --self-contained true
```

install.sh checks for `dotnet` before attempting this build and prints an error if it is not found.

---

### 9.10 dig

**Tool description:** DNS lookup utility from `bind9-dnsutils`. Standard DNS querying tool.

**Real binary:** `/usr/bin/dig` (full path used to avoid self-invocation)

**Engagement subdirectory:** `dns/`

**Output mechanism:** dig writes results exclusively to stdout. There is no native output-to-file flag. The wrapper redirects stdout to a timestamped file while also printing to the terminal (using `tee`).

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/dig — repkit wrapper for dig
# dig has no native file output; wrapper uses tee to write stdout to file

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir dns) || exit 1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="$OUTPUT_DIR/dig_${TIMESTAMP}.txt"

echo "[repkit] dig output -> $OUTFILE" >&2
/usr/bin/dig "$@" | tee "$OUTFILE"
exit ${PIPESTATUS[0]}
```

Note: `${PIPESTATUS[0]}` captures dig's exit code rather than tee's, preserving correct error propagation through the pipe.

**Output files written:** `~/engagements/<target>/dns/dig_<timestamp>.txt`

---

### 9.11 ffuf

**Tool description:** Fast web fuzzer by ffuf. Used for directory/file enumeration, parameter fuzzing, and vhost discovery.

**Real binary:** `ffuf` (go-installed)

**Engagement subdirectory:** `ffuf/`

**Output mechanism:** ffuf supports:
- `-o <file>`: output file path
- `-of <format>`: output format (`json`, `ejson`, `html`, `md`, `csv`, `all`)

The wrapper forces `-o "$OUTPUT_DIR/ffuf_<timestamp>.json"` and `-of json`. Using JSON format ensures machine-readable output for repcollect.

**Conflicting flag handling:** Strip `-o` and `-of` (and their values) from operator arguments.

**Wrapper:**

```bash
#!/usr/bin/env bash
# wrappers/ffuf — repkit wrapper for ffuf

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$SCRIPT_DIR/../lib/engagement.sh"

OUTPUT_DIR=$(ensure_engagement_dir ffuf) || exit 1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="$OUTPUT_DIR/ffuf_${TIMESTAMP}.json"

# Strip -o and -of flags
ARGS=()
skip_next=0
for arg in "$@"; do
    if [[ $skip_next -eq 1 ]]; then skip_next=0; continue; fi
    if [[ "$arg" == "-o" || "$arg" == "-of" ]]; then skip_next=1; continue; fi
    ARGS+=("$arg")
done

echo "[repkit] ffuf output -> $OUTFILE" >&2
ffuf -o "$OUTFILE" -of json "${ARGS[@]}"
exit $?
```

**Output files written:** `~/engagements/<target>/ffuf/ffuf_<timestamp>.json`

---

## 10. Error Cases

### 10.1 Wrapper Error Cases

All wrappers share these common error conditions via `lib/engagement.sh`:

| Condition | Message | Exit Code |
|---|---|---|
| No `~/.engagement` or `~/.engagement` is empty | `error: no active engagement. run 'rpt use <target>' first.` | 1 |
| `mkdir -p` for output directory fails | `error: could not create output directory <path>` | 1 |
| Real binary not found | `error: <tool> not found at <path>. run install.sh.` | 1 |

### 10.2 install.sh Error Cases

| Condition | Message | Exit Code |
|---|---|---|
| Run as root | `error: do not run install.sh as root. run as your operator user.` | 1 |
| `apt` not found | `error: apt not found. repkit requires a Debian-based system.` | 1 |
| `git` not found | `error: git is required.` | 1 |
| `python3` not found | `error: python3 is required.` | 1 |
| `pip3` not found | `error: pip3 is required.` | 1 |
| `go` not found | `warning: go not found. skipping go-installed tools: httpx, gowitness, ffuf.` (continue) | 0 |
| `tools.conf` not found | `error: tools.conf not found. run install.sh from the repkit/ directory.` | 1 |
| `dotnet` not found | `warning: dotnet not found. skipping TeamFiltration build.` (continue) | 0 |
| Individual tool install fails | `error: failed to install <tool>: <error>. continuing.` (continue) | 0 |

---

## 11. Implementation Order

The following order minimizes dependencies and allows each component to be tested before the next is built.

### Phase 1: Core Infrastructure

1. **`lib/engagement.sh`** — the shared library that all wrappers depend on. Write and test `get_active_engagement()` and `ensure_engagement_dir()` in isolation before writing any wrapper.

2. **`tools.conf`** — write the complete tool list with all install methods. No code; just the file. Verify the format parses correctly before building install.sh around it.

### Phase 2: install.sh

3. **`install.sh`** — implement all steps. Test in a Kali VM with a clean snapshot so idempotency can be verified by running the script twice. Build in this order within the script: sanity checks, dependency checks, directory creation, apt installs, pip installs, git clones, go installs, manual notices, wrapper symlinks, summary.

### Phase 3: Wrappers (in dependency order)

Implement wrappers in this order, from simplest to most complex:

4. **`wrappers/nmap`** — good first wrapper because `/usr/bin/nmap` is always available, `-oA` is well-understood, and argument stripping is straightforward. Validates the wrapper pattern end-to-end.

5. **`wrappers/dig`** — simplest stdout-capture pattern using `tee`. Validates the `${PIPESTATUS[0]}` pattern.

6. **`wrappers/httpx`** — standard `-o` flag pattern. Requires go toolchain to be working.

7. **`wrappers/ffuf`** — standard `-o -of` pattern with two flags to strip.

8. **`wrappers/gowitness`** — two output flags (`--screenshot-path` and `--db-path`), plus subdirectory creation.

9. **`wrappers/trufflehog`** — stdout-redirect pattern (no native output flag). Requires pip install.

10. **`wrappers/s3scanner`** — `--out-file` pattern. Requires pip install.

11. **`wrappers/canvass`** — `--output` pattern. Requires repcollect to be installed.

12. **`wrappers/cloud-enum`** — `-l` flag with Python invocation. Requires git clone to have succeeded.

13. **`wrappers/roadtools`** — most complex wrapper due to subcommand routing (`roadrecon gather` vs other subcommands). Implement after simpler wrappers.

14. **`wrappers/teamfiltration`** — requires dotnet build step. Implement last because the build is the most complex install step.

### Phase 4: Integration Testing

15. Provision a clean Kali Linux VM (snapshot before install).
16. Run `install.sh`. Verify all tools install. Verify symlinks exist in `~/bin/`.
17. Run `rpt new test.local`. Verify directory skeleton is created. Verify `~/.engagement` is written.
18. Run each wrapper against a test target (e.g., `nmap 127.0.0.1`, `dig @8.8.8.8 google.com`). Verify output appears in `~/engagements/test.local/<tool>/`.
19. Run `install.sh` a second time. Verify no errors and no duplicate installs.
20. Unset `~/.engagement`. Run a wrapper. Verify the error message is printed and the wrapper exits 1.

---

## 12. `rpt run` — Phase Orchestration

### 12.1 Overview

`rpt run` is a subcommand of `rpt` (in `repcollect/rpt.py`) that orchestrates running all tools for a given phase sequentially. It replaces the need to invoke each tool wrapper individually.

**Usage:**
```
rpt run -t <type> -p <phase>
```

**Flags:**

| Flag | Required | Values | Description |
|---|---|---|---|
| `-t` / `--type` | Yes | `ext` (more in future) | Engagement type. Determines output subfolder. |
| `-p` / `--phase` | Yes | `recon`, `cloud`, `scanning`, `spray`, `dns`, `web` | Phase to run. Determines which tools execute. |

### 12.2 Phase → Tool Mapping

| Phase | Tools (in order) |
|---|---|
| `recon` | canvass, trufflehog |
| `cloud` | cloud_enum, roadtools, s3scanner |
| `scanning` | nmap, httpx, gowitness |
| `spray` | teamfiltration |
| `dns` | dig |
| `web` | ffuf |

### 12.3 How It Works

1. Resolve the active engagement from `~/.engagement` (or `-T` flag if provided). Error if not set.
2. Set `ENGAGEMENT_TYPE=<type>` in the subprocess environment for all tool invocations.
3. For each tool in the phase (in order):
   a. Print which tool is about to run.
   b. Prompt the operator for required variables (see 13.4).
   c. Invoke the tool's wrapper (from `~/bin/<tool>`) with the prompted variables as arguments, with `ENGAGEMENT_TYPE` set in the environment.
   d. Stream the tool's stdout/stderr to the terminal.
   e. On non-zero exit: print a warning, ask operator whether to continue or abort. Default: continue.
4. Print a summary of which tools succeeded, failed, or were skipped.

Output for each tool goes to `~/engagements/<target>/<type>/<tool_subdir>/` automatically via the wrapper's `ensure_engagement_dir()` call.

### 12.4 Per-Tool Required Variables

Each tool prompts for only the variables it cannot infer from context. The active target domain is always available from `~/.engagement` and is never prompted.

| Tool | Prompted Variables |
|---|---|
| canvass | _(none — target domain is sufficient)_ |
| trufflehog | `Source type` (git/filesystem/s3/etc.), `Source target` (repo URL or path) |
| cloud_enum | `Keywords` (comma-separated company names/keywords for cloud enum) |
| roadtools | `Auth method` (device code / password / token), `Username` (if password auth) |
| s3scanner | `Keywords` (comma-separated terms to enumerate as bucket names) |
| nmap | `Target` (IP, CIDR, or hostname), `Scan type` (quick/full/udp — maps to nmap flag presets) |
| httpx | `Input file` (path to hosts/URLs list) or `Target` (single host) |
| gowitness | `Input file` (path to URLs list) or `Target URL` (single URL) |
| teamfiltration | `Domain`, `Users file` (path), `Password` |
| dig | `Domain`, `Record type` (A/MX/TXT/NS/ALL), `DNS server` (optional, default: system) |
| ffuf | `Target URL` (with FUZZ placeholder), `Wordlist` (path) |

### 12.5 Scan Type Presets for nmap

When nmap is run via `rpt run`, the operator selects a scan type shorthand rather than raw nmap flags:

| Preset | nmap flags |
|---|---|
| `quick` | `-T4 -F` |
| `full` | `-T4 -p-` |
| `udp` | `-sU -T4 --top-ports 100` |
| `service` | `-T4 -sV -sC` |

### 12.6 Output

Terminal output during `rpt run`:

```
rpt run — ext / recon
target: example.com
output: ~/engagements/example.com/ext/

[1/2] canvass
  running canvass against example.com...
  ✓ canvass done (output: ~/engagements/example.com/ext/recon/)

[2/2] trufflehog
  source type: git
  source target: https://github.com/example/example-repo
  running trufflehog...
  ✓ trufflehog done (output: ~/engagements/example.com/ext/trufflehog/)

✓ phase complete: 2/2 tools succeeded
```

### 12.7 Error Cases

| Condition | Behavior |
|---|---|
| No active engagement | Print error, exit 1 |
| Unknown type (`-t`) | Print error listing valid types, exit 1 |
| Unknown phase (`-p`) | Print error listing valid phases, exit 1 |
| `-t` or `-p` not provided | Print usage, exit 1 |
| Tool wrapper not found in `~/bin/` | Warn, skip tool, continue |
| Tool exits non-zero | Prompt operator: continue or abort |

### 12.8 Implementation Notes

- `rpt run` lives in `rpt.py` as a subcommand alongside the existing bundle behavior.
- It invokes wrapper scripts via `subprocess.run()` with the extended environment (`ENGAGEMENT_TYPE` set).
- Variable prompts use Python's `input()` — no external libraries.
- The phase → tool mapping and per-tool variable definitions are defined as a data structure in `rpt.py`, not in the collector `.py` files.

---

*End of repkit Design Document*
