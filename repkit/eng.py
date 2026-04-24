#!/usr/bin/env python3
"""eng — engagement manager for repkit."""

import os
import sys
from pathlib import Path

ENGAGEMENT_FILE = Path.home() / ".engagement"
ENGAGEMENTS_DIR = Path.home() / "engagements"

TOOL_SUBDIRS = [
    "recon", "trufflehog", "cloud", "roadtools", "s3scanner",
    "nmap", "httpx", "gowitness", "spray", "dns", "ffuf",
]

USAGE = """\
usage: eng <command> [args]
commands:
  new <target>    create a new engagement and set it as active
  use <target>    switch to an existing engagement
  current         print the active engagement
  list            list all engagements\
"""


def read_engagement() -> str | None:
    if ENGAGEMENT_FILE.exists():
        target = ENGAGEMENT_FILE.read_text().strip()
        return target if target else None
    return None


def write_engagement(target: str) -> None:
    ENGAGEMENT_FILE.write_text(target + "\n")
    ENGAGEMENT_FILE.chmod(0o600)


def validate_target(target: str) -> None:
    if not target:
        print("error: target name must not be empty", file=sys.stderr)
        sys.exit(1)
    if "/" in target or "\\" in target:
        print("error: target name must not contain path separators", file=sys.stderr)
        sys.exit(1)
    if target != target.strip():
        print("error: target name must not have leading or trailing whitespace", file=sys.stderr)
        sys.exit(1)


def cmd_new(args: list[str]) -> int:
    if not args:
        print("error: usage: eng new <target>", file=sys.stderr)
        return 1

    target = args[0]
    validate_target(target)

    target_dir = ENGAGEMENTS_DIR / target
    if target_dir.exists():
        print(f"error: engagement '{target}' already exists. use 'eng use {target}' to switch to it.", file=sys.stderr)
        return 1

    try:
        for subdir in TOOL_SUBDIRS:
            (target_dir / subdir).mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"error: could not create ~/engagements/{target}/: {e}", file=sys.stderr)
        return 1

    try:
        write_engagement(target)
    except OSError as e:
        print(f"error: could not write ~/.engagement: {e}", file=sys.stderr)
        return 1

    print(f"[+] engagement created: ~/engagements/{target}/")
    print(f"[+] active engagement set to: {target}")
    return 0


def cmd_use(args: list[str]) -> int:
    if not args:
        print("error: usage: eng use <target>", file=sys.stderr)
        return 1

    target = args[0]
    validate_target(target)

    target_dir = ENGAGEMENTS_DIR / target
    if not target_dir.exists():
        print(f"error: engagement '{target}' does not exist. run 'eng new {target}' to create it.", file=sys.stderr)
        return 1

    try:
        write_engagement(target)
    except OSError as e:
        print(f"error: could not write ~/.engagement: {e}", file=sys.stderr)
        return 1

    print(f"[+] active engagement set to: {target}")
    return 0


def cmd_current() -> int:
    target = read_engagement()
    if not target:
        print("error: no active engagement. run 'eng use <target>' first.", file=sys.stderr)
        return 1
    print(target)
    return 0


def cmd_list() -> int:
    if not ENGAGEMENTS_DIR.exists():
        print("no engagements found. run 'eng new <target>' to create one.")
        return 0

    entries = sorted(p.name for p in ENGAGEMENTS_DIR.iterdir() if p.is_dir())
    if not entries:
        print("no engagements found. run 'eng new <target>' to create one.")
        return 0

    active = read_engagement()
    for name in entries:
        marker = "*" if name == active else " "
        print(f"  {marker} {name}")
    return 0


def main() -> int:
    args = sys.argv[1:]

    if not args:
        print(USAGE)
        return 1

    cmd = args[0]
    rest = args[1:]

    if cmd == "new":
        return cmd_new(rest)
    elif cmd == "use":
        return cmd_use(rest)
    elif cmd == "current":
        return cmd_current()
    elif cmd == "list":
        return cmd_list()
    else:
        print(f"error: unknown command '{cmd}'. run 'eng' for usage.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
