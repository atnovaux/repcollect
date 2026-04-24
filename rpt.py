"""repcollect — red team output collector."""

import argparse
import importlib
import os
import pkgutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import collectors

__version__ = "0.1.0"

MAX_FILE_BYTES = 500 * 1024 * 1024
WARN_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024

VALID_TYPES = ["ext"]

PHASES = {
    "recon":    ["canvass", "trufflehog"],
    "cloud":    ["cloud-enum", "roadtools", "s3scanner"],
    "scanning": ["nmap", "httpx", "gowitness"],
    "dns":      ["dig"],
    "web":      ["ffuf"],
}

TOOL_PROMPTS = {
    "canvass":        [("domain (e.g. acme.com)", "domain")],
    "trufflehog":     [("source type (git/filesystem/s3)", "source_type"),
                       ("source target (repo URL or path)", "source_target")],
    "cloud-enum":     [("keywords, comma-separated (e.g. acme,acmecorp)", "keywords")],
    "roadtools":      [("auth method (devicecode/password/token)", "auth_method")],
    "s3scanner":      [("bucket names file path (or single keyword)", "input")],
    "nmap":           [("target (IP, CIDR, or hostname)", "target"),
                       ("scan type (quick/full/udp/service)", "scan_type")],
    "httpx":          [("input: file path or single host", "input")],
    "gowitness":      [("input: file path or single URL", "input")],
    "dig":            [("domain", "domain"),
                       ("record type (A/MX/TXT/NS/ANY)", "record_type")],
    "ffuf":           [("target URL with FUZZ placeholder", "url"),
                       ("wordlist path", "wordlist")],
}

NMAP_PRESETS = {
    "quick":   ["-T4", "-F"],
    "full":    ["-T4", "-p-"],
    "udp":     ["-sU", "-T4", "--top-ports", "100"],
    "service": ["-T4", "-sV", "-sC"],
}


@dataclass
class DetectedFile:
    role: str
    source_path: Path
    dest_rel_path: str
    size_bytes: int


@dataclass
class DetectionResult:
    tool_name: str
    subdir: str
    version: str | None
    found: bool
    files: list[DetectedFile] = field(default_factory=list)
    note: str | None = None


@dataclass
class SkippedFile:
    path: str
    size_bytes: int
    reason: str


def get_engagement_base() -> Path:
    base = os.environ.get("ENGAGEMENT_BASE")
    if base:
        return Path(base)
    return Path.home() / "engagements"


ENGAGEMENT_FILE = Path.home() / ".engagement"

TOOL_SUBDIRS = [
    "recon", "trufflehog", "cloud", "roadtools", "s3scanner",
    "nmap", "httpx", "gowitness", "spray", "dns", "ffuf",
]


def read_engagement_file() -> str | None:
    if ENGAGEMENT_FILE.exists():
        target = ENGAGEMENT_FILE.read_text().strip()
        return target if target else None
    return None


def write_engagement_file(target: str) -> None:
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


def get_target(args) -> str:
    if hasattr(args, "target") and args.target:
        return args.target
    target = read_engagement_file()
    if target:
        return target
    print("error: no target specified. run 'rpt use <target>' or pass -T.", file=sys.stderr)
    sys.exit(1)


def load_collectors() -> list:
    loaded = []
    for _, modname, ispkg in pkgutil.walk_packages(
        path=collectors.__path__,
        prefix=collectors.__name__ + ".",
        onerror=lambda x: None,
    ):
        if ispkg:
            continue
        mod = importlib.import_module(modname)
        if not all(hasattr(mod, x) for x in ("NAME", "SUBDIR", "FILES")):
            continue
        loaded.append(mod)
    return loaded


def scan_for_tools(target_dir: Path, etype: str) -> tuple[list[DetectionResult], list[SkippedFile]]:
    mods = load_collectors()
    results = []
    skipped = []
    type_dir = target_dir / etype

    for mod in mods:
        subdir_path = type_dir / mod.SUBDIR

        if not subdir_path.exists():
            results.append(DetectionResult(
                tool_name=mod.NAME,
                subdir=mod.SUBDIR,
                version=None,
                found=False,
                note=f"subdir {etype}/{mod.SUBDIR}/ not found",
            ))
            continue

        detected_files = []
        for role, pattern in mod.FILES.items():
            for match in subdir_path.glob(pattern):
                if match.is_file() and not match.name.startswith("."):
                    size = match.stat().st_size
                    dest = f"{mod.SUBDIR}/{match.name}"
                    if size > MAX_FILE_BYTES:
                        skipped.append(SkippedFile(
                            path=str(match),
                            size_bytes=size,
                            reason=f"exceeds {MAX_FILE_BYTES // (1024**2)} MB limit",
                        ))
                    else:
                        detected_files.append(DetectedFile(
                            role=role,
                            source_path=match,
                            dest_rel_path=dest,
                            size_bytes=size,
                        ))

        if not detected_files:
            results.append(DetectionResult(
                tool_name=mod.NAME,
                subdir=mod.SUBDIR,
                version=None,
                found=False,
                note=f"subdir {etype}/{mod.SUBDIR}/ exists but no matching files",
            ))
            continue

        detect_fn = getattr(mod, "detect_version", None)
        version = detect_fn(subdir_path) if detect_fn else None

        results.append(DetectionResult(
            tool_name=mod.NAME,
            subdir=mod.SUBDIR,
            version=version,
            found=True,
            files=detected_files,
        ))

    return results, skipped


def build_manifest(target: str, date_stamp: str, etype: str,
                   detections: list[DetectionResult],
                   skipped: list[SkippedFile]) -> dict:
    import datetime

    operator = os.environ.get("OPERATOR") or os.environ.get("USER") or "unknown"

    tools = []
    missing_tools = []

    for d in detections:
        if not d.found:
            missing_tools.append({"name": d.tool_name, "note": d.note})
        else:
            roles: dict[str, list[str]] = {}
            for f in d.files:
                roles.setdefault(f.role, []).append(f.dest_rel_path)
            tools.append({
                "name": d.tool_name,
                "version": d.version,
                "subdir": d.subdir,
                "file_count": len(d.files),
                "total_size_bytes": sum(f.size_bytes for f in d.files),
                "roles": roles,
            })

    return {
        "bundle_spec_version": 1,
        "collector_version": __version__,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
                          .isoformat().replace("+00:00", "Z"),
        "engagement": {
            "id": f"{target}-{etype}-{date_stamp}",
            "target_domain": target,
            "engagement_type": etype,
            "operator": operator,
            "hostname": os.uname().nodename,
        },
        "tools": tools,
        "missing_tools": missing_tools,
        "skipped_files": [
            {"path": s.path, "size_bytes": s.size_bytes, "reason": s.reason}
            for s in skipped
        ],
    }


def create_bundle(target: str, date_stamp: str, etype: str,
                  detections: list[DetectionResult],
                  manifest: dict, fmt: str) -> Path:
    import json
    import shutil
    import tarfile
    import tempfile
    import zipfile

    bundle_name = f"{target}-{etype}-{date_stamp}"
    output_path = Path(f"./{bundle_name}.{fmt}")

    if output_path.exists():
        print(
            f"error: output file already exists: {output_path}\n"
            "hint: delete it or rename it before re-running.",
            file=sys.stderr,
        )
        sys.exit(1)

    all_files = [f for d in detections if d.found for f in d.files]

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / bundle_name
        staging.mkdir()

        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        seen_dests: set[str] = set()
        for df in all_files:
            dest = staging / df.dest_rel_path
            if df.dest_rel_path in seen_dests:
                print(f"error: destination path collision: {df.dest_rel_path}", file=sys.stderr)
                sys.exit(1)
            seen_dests.add(df.dest_rel_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(df.source_path, dest)

        if fmt == "tar.gz":
            with tarfile.open(output_path, "w:gz") as tar:
                tar.add(staging, arcname=bundle_name)
        else:
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in staging.rglob("*"):
                    if f.is_file():
                        zf.write(f, arcname=f.relative_to(staging.parent))

    os.chmod(output_path, 0o600)
    return output_path


def build_tool_args(tool: str, prompted: dict, target: str) -> list[str]:
    if tool == "canvass":
        return [prompted["domain"]]
    elif tool == "trufflehog":
        return [prompted["source_type"], prompted["source_target"]]
    elif tool == "cloud-enum":
        return ["-k", prompted["keywords"]]
    elif tool == "roadtools":
        return ["roadrecon", "gather", f"--{prompted['auth_method']}"]
    elif tool == "s3scanner":
        inp = prompted["input"]
        if Path(inp).exists():
            return ["-bucket-file", inp]
        return ["-bucket", inp]
    elif tool == "nmap":
        preset = NMAP_PRESETS.get(prompted["scan_type"], NMAP_PRESETS["quick"])
        return preset + [prompted["target"]]
    elif tool == "httpx":
        inp = prompted["input"]
        return ["-l", inp] if Path(inp).exists() else ["-u", inp]
    elif tool == "gowitness":
        inp = prompted["input"]
        return ["scan", "file", "-f", inp] if Path(inp).exists() else ["scan", "single", "-u", inp]
    elif tool == "dig":
        record = prompted["record_type"]
        return [prompted["domain"], record]
    elif tool == "ffuf":
        return ["-u", prompted["url"], "-w", prompted["wordlist"]]
    return []


def cmd_new(args) -> int:
    target = args.target
    validate_target(target)

    engagements_dir = get_engagement_base()
    target_dir = engagements_dir / target
    if target_dir.exists():
        print(f"error: engagement '{target}' already exists. run 'rpt use {target}' to switch to it.", file=sys.stderr)
        return 1

    try:
        for subdir in TOOL_SUBDIRS:
            (target_dir / subdir).mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"error: could not create {target_dir}/: {e}", file=sys.stderr)
        return 1

    try:
        write_engagement_file(target)
    except OSError as e:
        print(f"error: could not write ~/.engagement: {e}", file=sys.stderr)
        return 1

    print(f"[+] engagement created: {target_dir}/")
    print(f"[+] active engagement set to: {target}")
    return 0


def cmd_use(args) -> int:
    target = args.target
    validate_target(target)

    target_dir = get_engagement_base() / target
    if not target_dir.exists():
        print(f"error: engagement '{target}' does not exist. run 'rpt new {target}' to create it.", file=sys.stderr)
        return 1

    try:
        write_engagement_file(target)
    except OSError as e:
        print(f"error: could not write ~/.engagement: {e}", file=sys.stderr)
        return 1

    print(f"[+] active engagement set to: {target}")
    return 0


def cmd_current(args) -> int:
    target = read_engagement_file()
    if not target:
        print("error: no active engagement. run 'rpt use <target>' first.", file=sys.stderr)
        return 1
    print(target)
    return 0


def cmd_list(args) -> int:
    engagements_dir = get_engagement_base()
    if not engagements_dir.exists():
        print("no engagements found. run 'rpt new <target>' to create one.")
        return 0

    entries = sorted(p.name for p in engagements_dir.iterdir() if p.is_dir())
    if not entries:
        print("no engagements found. run 'rpt new <target>' to create one.")
        return 0

    active = read_engagement_file()
    for name in entries:
        marker = "*" if name == active else " "
        print(f"  {marker} {name}")
    return 0


def cmd_run(args) -> int:
    etype = args.etype
    phase = args.phase

    if etype not in VALID_TYPES:
        print(f"error: unknown type '{etype}'. valid: {', '.join(VALID_TYPES)}", file=sys.stderr)
        return 1
    if phase not in PHASES:
        print(f"error: unknown phase '{phase}'. valid: {', '.join(PHASES)}", file=sys.stderr)
        return 1

    target = read_engagement_file()
    if not target:
        print("error: no active engagement. run 'rpt use <target>' first.", file=sys.stderr)
        return 1

    tools = PHASES[phase]
    print(f"rpt run — {etype} / {phase}")
    print(f"target:  {target}")
    print(f"output:  ~/engagements/{target}/{etype}/\n")

    succeeded = []
    failed = []

    bin_dir = Path.home() / "bin"

    for i, tool in enumerate(tools, 1):
        print(f"[{i}/{len(tools)}] {tool}")

        prompted = {}
        for prompt_text, key in TOOL_PROMPTS.get(tool, []):
            try:
                value = input(f"  {prompt_text}: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\naborted.", file=sys.stderr)
                return 1
            if not value:
                print(f"  skipping {tool} (no input provided)")
                prompted = None
                break
            prompted[key] = value

        if prompted is None:
            continue

        tool_args = build_tool_args(tool, prompted, target)
        wrapper = bin_dir / tool

        if not wrapper.exists():
            print(f"  warning: wrapper not found at {wrapper}. skipping.")
            failed.append(tool)
            continue

        env = os.environ.copy()
        env["ENGAGEMENT_TYPE"] = etype

        print(f"  running {tool}...")
        result = subprocess.run([str(wrapper)] + tool_args, env=env, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            print(f"  ✓ {tool} done")
            succeeded.append(tool)
        else:
            print(f"  ! {tool} exited {result.returncode}")
            failed.append(tool)
            try:
                cont = input("  continue to next tool? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print("\naborted.", file=sys.stderr)
                return 1
            if cont == "n":
                break

        print()

    print(f"✓ phase complete: {len(succeeded)}/{len(tools)} tools succeeded")
    if failed:
        print(f"  failed/skipped: {', '.join(failed)}")
    return 0


def cmd_collect(args) -> int:
    etype = args.etype
    fmt = args.fmt

    if etype not in VALID_TYPES:
        print(f"error: unknown type '{etype}'. valid: {', '.join(VALID_TYPES)}", file=sys.stderr)
        return 1

    target = get_target(args)
    base = get_engagement_base()
    target_dir = base / target

    if not target_dir.exists():
        print(
            f"error: engagement directory not found: {target_dir}\n"
            f"hint: run 'rpt new {target}' to create it",
            file=sys.stderr,
        )
        return 1

    if not (target_dir / etype).exists():
        print(
            f"error: no {etype}/ data found under {target_dir}\n"
            f"hint: run 'rpt run -t {etype} -p <phase>' first",
            file=sys.stderr,
        )
        return 1

    print(f"repcollect v{__version__}")
    print(f"target:  {target}  [{etype}]")
    print(f"scanning {target_dir}/{etype}/ ...\n")

    detections, skipped = scan_for_tools(target_dir, etype)

    found = [d for d in detections if d.found]
    missing = [d for d in detections if not d.found]

    for d in found:
        version_str = f", v{d.version}" if d.version else ""
        print(f"  ✓ {d.tool_name:<18} {len(d.files)} files   ({d.subdir}/{version_str})")
    for d in missing:
        print(f"  - {d.tool_name:<18} not found ({d.note})")

    if skipped:
        print()
        for s in skipped:
            print(f"  ! skipped {s.path} ({s.size_bytes // (1024**2)} MB — {s.reason})")

    if not found:
        print("\nerror: no tool outputs found.", file=sys.stderr)
        return 1

    from datetime import date
    date_stamp = date.today().strftime("%Y%m%d")

    manifest = build_manifest(target, date_stamp, etype, detections, skipped)

    total_size = sum(f.size_bytes for d in found for f in d.files)
    total_files = sum(len(d.files) for d in found)

    print(f"\ncreating bundle: ./{target}-{etype}-{date_stamp}.{fmt}")
    output_path = create_bundle(target, date_stamp, etype, detections, manifest, fmt)

    bundle_size = output_path.stat().st_size
    if bundle_size > WARN_BUNDLE_BYTES:
        print(f"  warning: bundle is {bundle_size // (1024**3):.1f} GB (over 2 GB threshold)")

    size_mb = total_size / (1024 * 1024)
    print(f"  {size_mb:.1f} MB, {total_files} files from {len(found)} tool(s)\n")
    print("✓ done")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="rpt")
    parser.add_argument("--version", action="version", version=f"rpt {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    new_p = subparsers.add_parser("new", help="create a new engagement and set it active")
    new_p.add_argument("target", help="target name (e.g. acmecorp)")

    use_p = subparsers.add_parser("use", help="switch to an existing engagement")
    use_p.add_argument("target", help="target name")

    subparsers.add_parser("current", help="print the active engagement")
    subparsers.add_parser("list", help="list all engagements")

    run_p = subparsers.add_parser("run", help="run tools for a phase")
    run_p.add_argument("-t", required=True, dest="etype", metavar="TYPE",
                       help=f"engagement type ({', '.join(VALID_TYPES)})")
    run_p.add_argument("-p", required=True, dest="phase", metavar="PHASE",
                       help=f"phase ({', '.join(PHASES)})")

    collect_p = subparsers.add_parser("collect", help="bundle tool output into an archive")
    collect_p.add_argument("-t", required=True, dest="etype", metavar="TYPE",
                           help=f"engagement type ({', '.join(VALID_TYPES)})")
    collect_p.add_argument("-T", "--target", help="target domain (default: from ~/.engagement)")
    collect_p.add_argument("--format", choices=["tar.gz", "zip"], default="tar.gz", dest="fmt")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    dispatch = {
        "new": cmd_new,
        "use": cmd_use,
        "current": cmd_current,
        "list": cmd_list,
        "run": cmd_run,
        "collect": cmd_collect,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
