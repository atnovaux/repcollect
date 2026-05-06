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

    # Default engagement type to ext if not set (rpt run overrides this).
    local etype="${ENGAGEMENT_TYPE:-ext}"
    local output_dir="$HOME/engagements/$target/$etype/$tool_subdir"

    if [[ ! -d "$output_dir" ]]; then
        mkdir -p "$output_dir" || {
            echo "error: could not create output directory $output_dir" >&2
            return 1
        }
    fi

    printf '%s' "$output_dir"
    return 0
}

# is_in_scope <target>
#   Returns 0 if <target> matches an entry in scope.txt or domains.txt,
#   1 otherwise.  Scope files are exact-string + suffix-match for hostnames
#   and prefix-match for CIDR-like entries (cheap heuristic, not RFC-perfect
#   subnet math).  Comments and blank lines ignored.
is_in_scope() {
    local target="$1"
    local engagement
    engagement=$(get_active_engagement) || return 1
    local base="$HOME/engagements/$engagement"

    local files=()
    [[ -f "$base/scope.txt"   ]] && files+=("$base/scope.txt")
    [[ -f "$base/domains.txt" ]] && files+=("$base/domains.txt")
    if [[ ${#files[@]} -eq 0 ]]; then
        # No scope defined — fail open (operator hasn't set boundaries yet).
        return 0
    fi

    local line
    for f in "${files[@]}"; do
        while IFS= read -r line; do
            line="${line%%#*}"           # strip comment
            line="${line##[[:space:]]}"  # ltrim
            line="${line%%[[:space:]]}"  # rtrim
            [[ -z "$line" ]] && continue
            # exact match, or suffix-match for hostnames (foo.example.com matches example.com)
            if [[ "$target" == "$line" ]] || [[ "$target" == *".$line" ]]; then
                return 0
            fi
        done < "$f"
    done
    return 1
}

# evidence_dir
#   ~/engagements/<active>/evidence/  — created on first call.
evidence_dir() {
    local engagement
    engagement=$(get_active_engagement) || return 1
    local d="$HOME/engagements/$engagement/evidence"
    mkdir -p "$d/logs" "$d/screenshots/auto" "$d/screenshots/manual" "$d/files"
    printf '%s' "$d"
}

# _json_escape <string>   — minimal escaping for embedding in audit.jsonl
# (use argv, not <<< — here-strings append a newline that breaks JSON keys)
_json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]), end="")' -- "$1"
}

# audit_event <kind> <key=val>...
#   Append a structured JSON line to evidence/audit.jsonl.  Each key=val pair
#   becomes a top-level field; values are JSON-escaped.  Numbers and booleans
#   pass through if the val starts with @raw: (e.g. @raw:0 or @raw:true).
audit_event() {
    local kind="$1"; shift
    local engagement
    engagement=$(get_active_engagement) || return 1
    local etype="${ENGAGEMENT_TYPE:-ext}"
    local operator="${OPERATOR:-${USER:-unknown}}"
    local host
    host=$(hostname 2>/dev/null || echo unknown)
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    local ev_dir
    ev_dir=$(evidence_dir) || return 1

    {
        printf '{"ts":%s,"kind":%s,"engagement":%s,"etype":%s,"operator":%s,"host":%s' \
            "$(_json_escape "$ts")" \
            "$(_json_escape "$kind")" \
            "$(_json_escape "$engagement")" \
            "$(_json_escape "$etype")" \
            "$(_json_escape "$operator")" \
            "$(_json_escape "$host")"
        local kv k v
        for kv in "$@"; do
            k="${kv%%=*}"
            v="${kv#*=}"
            if [[ "$v" == @raw:* ]]; then
                printf ',%s:%s' "$(_json_escape "$k")" "${v#@raw:}"
            else
                printf ',%s:%s' "$(_json_escape "$k")" "$(_json_escape "$v")"
            fi
        done
        printf '}\n'
    } >> "$ev_dir/audit.jsonl"
}

# _sha256 <file>  — print "<hex>" or empty on missing file
_sha256() {
    [[ -f "$1" ]] || { printf ''; return 0; }
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# audit_run <tool-name> <binary> [args...]
#   Run a tool, capture stdout+stderr to evidence/logs/<tool>_<ts>.{raw,log},
#   strip CR-redraws to a clean log, hash both, and append a tool_run audit
#   event.  Returns the tool's original exit code.
audit_run() {
    local tool="$1"; shift
    local binary="$1"; shift
    local engagement
    engagement=$(get_active_engagement) || return 1
    local ev_dir
    ev_dir=$(evidence_dir) || return 1

    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local raw="$ev_dir/logs/${tool}_${ts}.raw.log"
    local clean="$ev_dir/logs/${tool}_${ts}.log"
    local cmd_repr="$binary"
    local a
    for a in "$@"; do
        cmd_repr+=" $(printf '%q' "$a")"
    done

    # Snapshot output dir mtime before run so we can identify new files after.
    local etype="${ENGAGEMENT_TYPE:-ext}"
    local snapshot
    snapshot=$(mktemp)
    find "$HOME/engagements/$engagement/$etype" -type f -newer /dev/null -printf '%T@ %p\n' 2>/dev/null | sort > "$snapshot" || true

    local start_epoch
    start_epoch=$(date +%s.%N 2>/dev/null || date +%s)

    # Run with combined stdout+stderr captured to raw.log; tee to terminal too.
    set +e
    "$binary" "$@" 2>&1 | tee "$raw"
    local rc=${PIPESTATUS[0]}
    set -e

    local end_epoch
    end_epoch=$(date +%s.%N 2>/dev/null || date +%s)
    local duration
    duration=$(awk "BEGIN {printf \"%.3f\", $end_epoch - $start_epoch}")

    # Strip CR-redraws: keep only segment after the last \r per line.
    sed -E 's/.*\r//g' "$raw" > "$clean" 2>/dev/null || cp "$raw" "$clean"

    local raw_hash clean_hash
    raw_hash=$(_sha256 "$raw")
    clean_hash=$(_sha256 "$clean")

    # Find any output files created since snapshot.
    local outputs_json="[]"
    local newer
    newer=$(mktemp)
    find "$HOME/engagements/$engagement/$etype" -type f -newer "$snapshot" 2>/dev/null \
        | grep -v "^$ev_dir/" | sort > "$newer" || true
    if [[ -s "$newer" ]]; then
        outputs_json=$(
            python3 - "$newer" "$HOME/engagements/$engagement" <<'PY'
import json, os, sys, hashlib
listfile, eng_root = sys.argv[1], sys.argv[2]
out = []
with open(listfile) as f:
    for path in (l.strip() for l in f if l.strip()):
        try:
            size = os.path.getsize(path)
            with open(path, 'rb') as fh:
                h = hashlib.sha256(fh.read()).hexdigest()
            rel = os.path.relpath(path, eng_root)
            out.append({"path": rel, "size": size, "sha256": h})
        except OSError:
            continue
print(json.dumps(out))
PY
        )
    fi

    rm -f "$snapshot" "$newer"

    audit_event "tool_run" \
        "tool=$tool" \
        "command=$cmd_repr" \
        "exit_code=@raw:$rc" \
        "duration_s=@raw:$duration" \
        "log_file=evidence/logs/${tool}_${ts}.log" \
        "log_sha256=$clean_hash" \
        "raw_log_sha256=$raw_hash" \
        "outputs=@raw:$outputs_json"

    return "$rc"
}

# scope_guard <args...>
#   Examines all args, identifies anything that looks like a host/CIDR/URL,
#   and rejects out-of-scope entries.  Skips flags (-x), file paths, and
#   ambiguous strings.  Override with OPSEC_ALLOW_OUT_OF_SCOPE=1.
scope_guard() {
    local violations=()
    local arg host
    for arg in "$@"; do
        # Skip flags
        [[ "$arg" == -* ]] && continue
        # Skip readable files (treated as input lists, not single targets)
        [[ -f "$arg" ]] && continue

        # Strip URL scheme + path to get bare host
        host="$arg"
        if [[ "$host" =~ ^https?:// ]]; then
            host="${host#http://}"
            host="${host#https://}"
            host="${host%%/*}"
            host="${host%%:*}"
        fi

        # Only check things that look like hostnames, IPv4, or CIDR.
        if [[ ! "$host" =~ ^([a-zA-Z0-9_.-]+|[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?)$ ]]; then
            continue
        fi
        # Ignore short bareword args like 'all', 'quick', 'A' — must contain dot or be IP-shaped.
        if [[ "$host" != *.* ]]; then
            continue
        fi

        if ! is_in_scope "$host"; then
            violations+=("$host")
        fi
    done

    if [[ ${#violations[@]} -eq 0 ]]; then
        return 0
    fi

    # Audit-log every scope decision involving violations.
    local v action
    if [[ "${OPSEC_ALLOW_OUT_OF_SCOPE:-0}" == "1" ]]; then
        action="overridden"
    else
        action="rejected"
    fi
    for v in "${violations[@]}"; do
        audit_event "scope_violation" "target=$v" "action=$action" 2>/dev/null || true
    done

    if [[ "$action" == "overridden" ]]; then
        echo "[repkit] OPSEC_ALLOW_OUT_OF_SCOPE=1 — proceeding with out-of-scope: ${violations[*]}" >&2
        return 0
    fi

    echo "error: out-of-scope target(s): ${violations[*]}" >&2
    echo "       not in scope.txt or domains.txt" >&2
    echo "       set OPSEC_ALLOW_OUT_OF_SCOPE=1 to override (logs the override)" >&2
    return 1
}
