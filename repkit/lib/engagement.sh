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
