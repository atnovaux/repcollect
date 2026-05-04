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

    if [[ "${OPSEC_ALLOW_OUT_OF_SCOPE:-0}" == "1" ]]; then
        echo "[repkit] OPSEC_ALLOW_OUT_OF_SCOPE=1 — proceeding with out-of-scope: ${violations[*]}" >&2
        return 0
    fi

    echo "error: out-of-scope target(s): ${violations[*]}" >&2
    echo "       not in scope.txt or domains.txt" >&2
    echo "       set OPSEC_ALLOW_OUT_OF_SCOPE=1 to override (logs the override)" >&2
    return 1
}
