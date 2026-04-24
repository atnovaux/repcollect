"""Collector for TruffleHog (secret scanning)."""

NAME = "trufflehog"
SUBDIR = "trufflehog"

FILES = {
    "results_json": "*.json",
    "results_txt":  "*.txt",
}
