"""Detector for canvass (M365/Entra ID pre-engagement recon tool)."""

import re
from pathlib import Path

NAME = "canvass"
SUBDIR = "recon"

FILES = {
    "aad_raw":          "aad-raw.json",
    "dns_raw":          "dns-raw.json",
    "cloud_raw":        "cloud-raw.json",
    "crtsh_raw":        "crtsh-raw.json",
    "brief_md":         "*_brief.md",
    "brief_txt":        "*_brief.txt",
    "summary_txt":      "*_summary.txt",
    "subdomains_txt":   "*_subdomains.txt",
    "all_hosts_txt":    "*_all-hosts.txt",
    "emails_txt":       "*_emails.txt",
    "technologies_txt": "*_technologies.txt",
    "http_fp_txt":      "*_http-fingerprints.txt",
    "run_log":          "*_run.log",
}


def detect_version(subdir_path: Path) -> str | None:
    for brief in subdir_path.glob("*_brief.md"):
        try:
            head = brief.read_text(errors="replace")[:2000]
            for line in head.splitlines():
                m = re.search(r"canvass\s+v(\d[\d.]+)", line, re.IGNORECASE)
                if m:
                    return m.group(1)
        except OSError:
            continue
    return None
