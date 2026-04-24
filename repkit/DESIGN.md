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
- Kali engagement boxes typically run as root; install.sh does NOT reject running as root. It will use `sudo` where needed (e.g., `apt install`) but makes no assumption about the current user.
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

See [repkit/tools.conf](tools.conf) for the authoritative tool list. Current contents:

```
# ── Recon / OSINT ──────────────────────────────────────────────────────────
git:https://github.com/atnovaux/canvass.git
git:https://github.com/trufflesecurity/trufflehog.git

# ── Cloud / Identity ───────────────────────────────────────────────────────
git:https://github.com/initstring/cloud_enum
pip:roadtools
git:https://github.com/sa7mon/S3Scanner.git

# ── Active Scanning ────────────────────────────────────────────────────────
apt:nmap
go:github.com/projectdiscovery/httpx/cmd/httpx
go:github.com/sensepost/gowitness

# ── User Enum & Password Spray ─────────────────────────────────────────────
git:https://github.com/Flangvik/TeamFiltration

# ── DNS / Email ────────────────────────────────────────────────────────────
apt:bind9-dnsutils

# ── Web Discovery ──────────────────────────────────────────────────────────
go:github.com/ffuf/ffuf/v2
```

### 6.3 Tool Install Method Rationale

| Tool | Method | Rationale |
|---|---|---|
| canvass | git | Cloned from upstream; `brief.py` run via the pytools venv python |
| trufflehog | git | Go source; built via `go install ./...` during `install_git` |
| cloud_enum | git | Single-script Python tool; requirements installed into pytools venv |
| roadtools | pip | Official PyPI package; installs `roadrecon` and `roadtx` CLIs into the pytools venv |
| s3scanner | git | Go source; built via `go install ./...` during `install_git` |
| nmap | apt | Standard Kali package; pinned for explicitness |
| httpx | go | Official `go install` from projectdiscovery |
| gowitness | go | Official `go install` from sensepost |
| TeamFiltration | git | .NET tool; cloned, built via `dotnet publish -c Release -r linux-x64 --self-contained true` |
| dig | apt | Part of `bind9-dnsutils` |
| ffuf | go | Official `go install` |

All Python tools (canvass, cloud_enum, roadtools) install into `~/tools/pytools_venv/` — never into the system Python or repcollect's rpt venv. This isolates them from Kali's PEP 668 enforcement and from each other.

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

The wrapper files in `repkit/wrappers/` are the source of truth. Each wrapper sources `lib/engagement.sh`, calls `ensure_engagement_dir <subdir>` to resolve the output directory, and invokes the real tool with output flags pinned to that directory. Per-tool details:

| Wrapper | Real binary path | Engagement subdir | Output mechanism |
|---|---|---|---|
| [canvass](wrappers/canvass) | `~/tools/pytools_venv/bin/python3 ~/tools/canvass/brief.py` | `recon/` | Forces `--output-dir <dir>`; also wipes `~/.bbot/scans/` before run to prevent cross-target cache contamination |
| [trufflehog](wrappers/trufflehog) | `~/go/bin/trufflehog` | `trufflehog/` | Forces `--json` and pipes stdout via `tee` to `trufflehog_<timestamp>.json`; uses `${PIPESTATUS[0]}` for exit code |
| [cloud-enum](wrappers/cloud-enum) | `~/tools/pytools_venv/bin/python3 ~/tools/cloud_enum/cloud_enum.py` | `cloud/` | Forces `-l <file>` to `cloud_enum_<timestamp>.txt` |
| [roadtools](wrappers/roadtools) | `~/tools/pytools_venv/bin/roadrecon` / `roadtx` | `roadtools/` | Routes `roadrecon gather` with `-d <run_dir>/roadrecon.db`; `roadtx` runs inside `<run_dir>/` |
| [s3scanner](wrappers/s3scanner) | `~/go/bin/s3scanner` | `s3scanner/` | Forces `-json`, pipes stdout via `tee` to `s3scanner_<timestamp>.json` |
| [nmap](wrappers/nmap) | `/usr/bin/nmap` | `nmap/` | Forces `-oA <basename>` (writes `.nmap`, `.xml`, `.gnmap`) |
| [httpx](wrappers/httpx) | `~/go/bin/httpx` | `httpx/` | Forces `-json -o <file>` to `httpx_<timestamp>.json` |
| [gowitness](wrappers/gowitness) | `~/go/bin/gowitness` | `gowitness/` | Forces `--screenshot-path <dir>/screenshots/` and `--db-path <dir>/gowitness.sqlite3` |
| [teamfiltration](wrappers/teamfiltration) | `~/tools/TeamFiltration/…/net9.0/linux-x64/publish/TeamFiltration` | `spray/` | Forces `--outpath <dir>` |
| [dig](wrappers/dig) | `/usr/bin/dig` | `dns/` | Pipes stdout via `tee` to `dig_<timestamp>.txt` |
| [ffuf](wrappers/ffuf) | `~/go/bin/ffuf` | `ffuf/` | Forces `-o <file> -of json` to `ffuf_<timestamp>.json` |

**Conflicting-flag handling:** every wrapper that forces an output flag also strips that flag (and its value) from `"$@"` before invocation, so operator-supplied overrides don't conflict.

**Absolute paths:** every wrapper invokes the real binary by absolute path rather than by name, so `~/bin/<tool>` (the wrapper itself) never recursively resolves back to itself when the wrapper is first in `$PATH`.

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
| `-p` / `--phase` | Yes | `recon`, `cloud`, `scanning`, `dns`, `web` | Phase to run. Determines which tools execute. |

### 12.2 Phase → Tool Mapping

| Phase | Tools (in order) |
|---|---|
| `recon` | canvass |
| `cloud` | cloud_enum, roadtools, s3scanner |
| `scanning` | nmap, httpx, gowitness |
| `dns` | dig |
| `web` | ffuf |

**Not in any phase** (run manually — they need specific input that isn't safe to auto-prompt):
- `trufflehog` — requires a source (git repo / filesystem / s3 bucket)
- `teamfiltration` — authentication attacks; too dangerous to mass-run via orchestration

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
| canvass | `domain` (target) |
| cloud_enum | `keywords` (comma-separated, e.g. `example,examplecorp`) |
| roadtools | `auth method` (devicecode/password/token) |
| s3scanner | `input` (bucket names file path or single keyword) |
| nmap | `target` (IP, CIDR, or hostname), `scan type` (quick/full/udp/service) |
| httpx | `input` (file path or single host) |
| gowitness | `input` (file path or single URL) |
| dig | `domain`, `record type` (A/MX/TXT/NS/ANY) |
| ffuf | `url` (with FUZZ placeholder), `wordlist` (path) |

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
