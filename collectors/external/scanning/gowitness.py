"""Collector for gowitness (web screenshot tool)."""

NAME = "gowitness"
SUBDIR = "gowitness"

FILES = {
    "db":                "gowitness.sqlite3",
    "report":            "*.html",
    "results_jsonl":     "*.jsonl",
    "results_json":      "*.json",
    "screenshots_jpeg":  "screenshots/*.jpeg",
    "screenshots_jpg":   "screenshots/*.jpg",
    "screenshots_png":   "screenshots/*.png",
}
