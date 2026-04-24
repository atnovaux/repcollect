"""repcollect — red team output collector."""

import argparse
import importlib
import os
import pkgutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import collectors

__version__ = "0.1.0"

MAX_FILE_BYTES = 500 * 1024 * 1024  # 500 MB
WARN_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB


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


def get_target(args) -> str:
    if args.target:
        return args.target
    env = os.environ.get("ENGAGEMENT")
    if env:
        return env
    print("error: no target specified. set $ENGAGEMENT or pass --target.", file=sys.stderr)
    sys.exit(1)


def load_collectors() -> list:
    loaded = []
    for _, name, _ in pkgutil.iter_modules(collectors.__path__):
        mod = importlib.import_module(f"collectors.{name}")
        if not all(hasattr(mod, x) for x in ("NAME", "SUBDIR", "FILES")):
            continue
        loaded.append(mod)
    return loaded


def scan_for_tools(target_dir: Path) -> tuple[list[DetectionResult], list[SkippedFile]]:
    mods = load_collectors()
    results = []
    skipped = []

    for mod in mods:
        subdir_path = target_dir / mod.SUBDIR

        if not subdir_path.exists():
            results.append(DetectionResult(
                tool_name=mod.NAME,
                subdir=mod.SUBDIR,
                version=None,
                found=False,
                note=f"subdir {mod.SUBDIR}/ not found",
            ))
            continue

        detected_files = []
        for role, pattern in mod.FILES.items():
            matches = list(subdir_path.glob(pattern))
            for match in matches:
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
                note=f"subdir {mod.SUBDIR}/ exists but no matching files",
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


def build_manifest(target: str, date_stamp: str, detections: list[DetectionResult],
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
            "id": f"{target}-{date_stamp}",
            "target_domain": target,
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


def create_bundle(target: str, date_stamp: str, detections: list[DetectionResult],
                  manifest: dict, fmt: str) -> Path:
    import json
    import shutil
    import tarfile
    import tempfile
    import zipfile

    bundle_name = f"{target}-{date_stamp}"
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

        # write manifest
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        # copy detected files preserving subdir structure
        seen_dests: set[str] = set()
        for df in all_files:
            dest = staging / df.dest_rel_path
            if df.dest_rel_path in seen_dests:
                print(f"error: destination path collision: {df.dest_rel_path}", file=sys.stderr)
                sys.exit(1)
            seen_dests.add(df.dest_rel_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(df.source_path, dest)

        # create archive
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


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="rpt",
        description="Collect red team tool output into a transferable bundle.",
    )
    parser.add_argument("--target", help="Target domain (or set $ENGAGEMENT)")
    parser.add_argument("--format", choices=["tar.gz", "zip"], default="tar.gz", dest="fmt")
    parser.add_argument("--version", action="version", version=f"rpt {__version__}")
    args = parser.parse_args()

    print(f"repcollect v{__version__}")

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

    print(f"target: {target}")
    print(f"scanning {target_dir}/ ...\n")

    detections, skipped = scan_for_tools(target_dir)

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

    manifest = build_manifest(target, date_stamp, detections, skipped)

    total_size = sum(f.size_bytes for d in found for f in d.files)
    total_files = sum(len(d.files) for d in found)

    print(f"\ncreating bundle: ./{target}-{date_stamp}.{args.fmt}")

    output_path = create_bundle(target, date_stamp, detections, manifest, args.fmt)

    bundle_size = output_path.stat().st_size
    if bundle_size > WARN_BUNDLE_BYTES:
        print(f"  warning: bundle is {bundle_size // (1024**3):.1f} GB (over 2 GB threshold)")

    size_mb = total_size / (1024 * 1024)
    print(f"  {size_mb:.1f} MB, {total_files} files from {len(found)} tool(s)\n")
    print("✓ done")

    return 0


if __name__ == "__main__":
    sys.exit(main())
