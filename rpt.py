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
    "spray":    ["teamfiltration"],
    "dns":      ["dig"],
    "web":      ["ffuf"],
}

TOOL_PROMPTS = {
    "canvass":        [],
    "trufflehog":     [("source type (git/filesystem/s3)", "source_type"),
                       ("source target (repo URL or path)", "source_target")],
    "cloud-enum":     [("keywords, comma-separated (e.g. acme,acmecorp)", "keywords")],
    "roadtools":      [("auth method (devicecode/password/token)", "auth_method")],
    "s3scanner":      [("bucket names file path (or single keyword)", "input")],
    "nmap":           [("target (IP, CIDR, or hostname)", "target"),
                       ("scan type (quick/full/udp/service)", "scan_type")],
    "httpx":          [("input: file path or single host", "input")],
    "gowitness":      [("input: file path or single URL", "input")],
    "teamfiltration": [("domain", "domain"),
                       ("users file path", "users_file"),
                       ("password", "password")],
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


def read_engagement_file() -> str | None:
    f = Path.home() / ".engagement"
    if f.exists():
        target = f.read_text().strip()
        return target if target else None
    return None


def get_target(args) -> str:
    if hasattr(args, "target") and args.target:
        return args.target
    target = read_engagement_file()
    if target:
        return target
    print("error: no target specified. run 'eng use <target>' or pass -T.", file=sys.stderr)
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


def scan_for_tools(target_dir: Path, eng_type: str) -> tuple[list[DetectionResult], list[SkippedFile]]:
    mods = load_collectors()
    results = []
    skipped = []
    type_dir = target_dir / eng_type

    for mod in mods:
        subdir_path = type_dir / mod.SUBDIR

        if not subdir_path.exists():
            results.append(DetectionResult(
                tool_name=mod.NAME,
                subdir=mod.SUBDIR,
                version=None,
                found=False,
                note=f"subdir {eng_type}/{mod.SUBDIR}/ not found",
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
                note=f"subdir {eng_type}/{mod.SUBDIR}/ exists but no matching files",
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


def build_manifest(target: str, date_stamp: str, eng_type: str,
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
            "id": f"{target}-{eng_type}-{date_stamp}",
            "target_domain": target,
            "engagement_type": eng_type,
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


def create_bundle(target: str, date_stamp: str, eng_type: str,
                  detections: list[DetectionResult],
                  manifest: dict, fmt: str) -> Path:
    import json
    import shutil
    import tarfile
    import tempfile
    import zipfile

    bundle_name = f"{target}-{eng_type}-{date_stamp}"
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
        return [target]
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
    elif tool == "teamfiltration":
        return ["--spray", "--domain", prompted["domain"],
                "--users", prompted["users_file"],
                "--password", prompted["password"]]
    elif tool == "dig":
        record = prompted["record_type"]
        return [prompted["domain"], record]
    elif tool == "ffuf":
        return ["-u", prompted["url"], "-w", prompted["wordlist"]]
    return []


def cmd_run(args) -> int:
    eng_type = args.eng_type
    phase = args.phase

    if eng_type not in VALID_TYPES:
        print(f"error: unknown type '{eng_type}'. valid: {', '.join(VALID_TYPES)}", file=sys.stderr)
        return 1
    if phase not in PHASES:
        print(f"error: unknown phase '{phase}'. valid: {', '.join(PHASES)}", file=sys.stderr)
        return 1

    target = read_engagement_file()
    if not target:
        print("error: no active engagement. run 'eng use <target>' first.", file=sys.stderr)
        return 1

    tools = PHASES[phase]
    print(f"rpt run — {eng_type} / {phase}")
    print(f"target:  {target}")
    print(f"output:  ~/engagements/{target}/{eng_type}/\n")

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
        env["ENGAGEMENT_TYPE"] = eng_type

        print(f"  running {tool}...")
        result = subprocess.run([str(wrapper)] + tool_args, env=env)

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
    eng_type = args.eng_type
    fmt = args.fmt

    if eng_type not in VALID_TYPES:
        print(f"error: unknown type '{eng_type}'. valid: {', '.join(VALID_TYPES)}", file=sys.stderr)
        return 1

    target = get_target(args)
    base = get_engagement_base()
    target_dir = base / target

    if not target_dir.exists():
        print(
            f"error: engagement directory not found: {target_dir}\n"
            f"hint: run 'eng new {target}' to create it (requires repkit)",
            file=sys.stderr,
        )
        return 1

    if not (target_dir / eng_type).exists():
        print(
            f"error: no {eng_type}/ data found under {target_dir}\n"
            f"hint: run 'rpt run -t {eng_type} -p <phase>' first",
            file=sys.stderr,
        )
        return 1

    print(f"repcollect v{__version__}")
    print(f"target:  {target}  [{eng_type}]")
    print(f"scanning {target_dir}/{eng_type}/ ...\n")

    detections, skipped = scan_for_tools(target_dir, eng_type)

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

    manifest = build_manifest(target, date_stamp, eng_type, detections, skipped)

    total_size = sum(f.size_bytes for d in found for f in d.files)
    total_files = sum(len(d.files) for d in found)

    print(f"\ncreating bundle: ./{target}-{eng_type}-{date_stamp}.{fmt}")
    output_path = create_bundle(target, date_stamp, eng_type, detections, manifest, fmt)

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

    run_p = subparsers.add_parser("run", help="run tools for a phase")
    run_p.add_argument("-t", required=True, dest="eng_type", metavar="TYPE",
                       help=f"engagement type ({', '.join(VALID_TYPES)})")
    run_p.add_argument("-p", required=True, dest="phase", metavar="PHASE",
                       help=f"phase ({', '.join(PHASES)})")

    collect_p = subparsers.add_parser("collect", help="bundle tool output into an archive")
    collect_p.add_argument("-t", required=True, dest="eng_type", metavar="TYPE",
                           help=f"engagement type ({', '.join(VALID_TYPES)})")
    collect_p.add_argument("-T", "--target", help="target domain (default: from ~/.engagement)")
    collect_p.add_argument("--format", choices=["tar.gz", "zip"], default="tar.gz", dest="fmt")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "run":
        return cmd_run(args)
    elif args.command == "collect":
        return cmd_collect(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
