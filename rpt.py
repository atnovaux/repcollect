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
    "recon":    ["canvass"],
    "cloud":    ["cloud-enum", "roadtools", "s3scanner"],
    "scanning": ["nmap", "httpx", "gowitness"],
    "dns":      ["dig"],
    "web":      ["ffuf"],
    # auto: OSINT + probing + scanning pipeline, minimal prompting.
    # Each tool's input defaults to the previous tool's output where possible.
    # Excludes auth-gated tools (roadtools, teamfiltration) and source-specific
    # tools (trufflehog, s3scanner) — those stay manual.
    "auto":     ["canvass", "nmap", "httpx", "gowitness", "cloud-enum", "ffuf"],
}

FFUF_DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

TOOL_PROMPTS = {
    "canvass":        [("root domain (e.g. example.com)", "domain")],
    "cloud-enum":     [("keywords, comma-separated (e.g. example,examplecorp)", "keywords")],
    "roadtools":      [("auth method (devicecode/password/token)", "auth_method")],
    "s3scanner":      [("bucket names file path OR single bucket keyword", "input")],
    "nmap":           [("target (scope file path preferred, or single IP/CIDR/hostname)", "target"),
                       ("scan type (quick/full/udp/service)", "scan_type")],
    "httpx":          [("host list file (from canvass subdomains) — press Enter to auto-chain", "input")],
    "gowitness":      [("URL list file (from httpx) — press Enter to auto-chain", "input")],
    "dig":            [("domain", "domain"),
                       ("record type (A/MX/TXT/NS/ANY)", "record_type")],
    "ffuf":           [("target URL (MUST include FUZZ placeholder, e.g. https://example.com/FUZZ)", "url"),
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

TOOL_SUBDIR_MAP = {
    "canvass":        "recon",
    "trufflehog":     "trufflehog",
    "cloud-enum":     "cloud",
    "roadtools":      "roadtools",
    "s3scanner":      "s3scanner",
    "nmap":           "nmap",
    "httpx":          "httpx",
    "gowitness":      "gowitness",
    "teamfiltration": "spray",
    "dig":            "dns",
    "ffuf":           "ffuf",
}


def read_engagement_file() -> str | None:
    if ENGAGEMENT_FILE.exists():
        target = ENGAGEMENT_FILE.read_text().strip()
        return target if target else None
    return None


def write_engagement_file(target: str) -> None:
    ENGAGEMENT_FILE.write_text(target + "\n")
    ENGAGEMENT_FILE.chmod(0o600)


def prompt_default(tool: str, key: str, target: str, etype: str = "ext",
                   context: dict | None = None) -> str | None:
    """Return a pre-filled default for a given tool prompt, if one applies.

    Chains tool outputs together:
      - httpx input     → newest <recon>/*_subdomains.txt (from canvass), else scope.txt
      - gowitness input → newest <httpx>/*_urls.txt, else scope.txt
      - nmap target     → scope.txt if present
      - nmap scan_type  → "quick"
      - dig record_type → "A"
      - ffuf url        → https://<target>/FUZZ
      - ffuf wordlist   → first of FFUF_DEFAULT_WORDLISTS that exists
    """
    base = get_engagement_base() / target
    scope = base / "scope.txt"
    has_scope = scope.is_file() and scope.stat().st_size > 0

    def _newest(glob_path: Path, pattern: str) -> Path | None:
        if not glob_path.is_dir():
            return None
        matches = sorted(glob_path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        return matches[0] if matches else None

    if tool == "nmap" and key == "target" and has_scope:
        return str(scope)
    if tool == "nmap" and key == "scan_type":
        return "quick"
    if tool == "dig" and key == "record_type":
        return "A"

    if tool == "httpx" and key == "input":
        # If canvass ran for multiple domains, aggregate their subdomain lists.
        recon = base / etype / "recon"
        if recon.is_dir():
            subs_files = list(recon.glob("*_subdomains.txt"))
            if len(subs_files) > 1:
                agg = aggregate_subdomains(target, etype)
                if agg:
                    return str(agg)
            elif len(subs_files) == 1:
                return str(subs_files[0])
        if has_scope:
            return str(scope)

    if tool == "gowitness" and key == "input":
        urls = _newest(base / etype / "httpx", "*_urls.txt")
        if urls:
            return str(urls)
        if has_scope:
            return str(scope)

    # Prefer domains.txt[0] → canvass-prompted domain → engagement name.
    domains_list = read_domains(target)
    primary = (
        domains_list[0] if domains_list
        else (context or {}).get("canvass", {}).get("domain")
        or target
    )

    if tool == "ffuf":
        if key == "url":
            return f"https://{primary}/FUZZ"
        if key == "wordlist":
            for candidate in FFUF_DEFAULT_WORDLISTS:
                if Path(candidate).is_file():
                    return candidate

    return None


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


def build_summary(target: str, etype: str, date_stamp: str,
                  detections: list[DetectionResult], eng_root: Path) -> str:
    """Markdown summary of a bundle — signal only, not full output.

    Designed to be short enough for an LLM context window. Per-tool extractors
    are defensive: any parse failure is silently swallowed and the tool just
    shows its file count.
    """
    import json

    lines: list[str] = []
    lines.append(f"# engagement summary: {target}")
    lines.append("")
    lines.append(f"- type: `{etype}`")
    lines.append(f"- bundle date: `{date_stamp}`")

    scope = eng_root / "scope.txt"
    if scope.is_file():
        scope_targets = [
            l.strip() for l in scope.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        lines.append(f"- scope entries: {len(scope_targets)}")

    domains_file = eng_root / "domains.txt"
    if domains_file.is_file():
        dom_list = [
            l.strip() for l in domains_file.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        lines.append(f"- root domains: {len(dom_list)}  ({', '.join(dom_list) if dom_list else 'none'})")
    lines.append("")

    # Per-tool signal extraction.
    type_dir = eng_root / etype
    ran = [d for d in detections if d.found]
    if not ran:
        lines.append("_no tool output in this bundle._")
        return "\n".join(lines) + "\n"

    lines.append("## tools")
    lines.append("")
    for d in ran:
        subdir = type_dir / d.subdir
        extracted = _extract_tool_signal(d.tool_name, subdir)
        version = f" v{d.version}" if d.version else ""
        lines.append(f"### {d.tool_name}{version}  — {len(d.files)} file(s)")
        if extracted:
            lines.append("")
            lines.extend(extracted)
        lines.append("")

    return "\n".join(lines) + "\n"


def _extract_tool_signal(tool: str, subdir: Path) -> list[str]:
    """Return a short list of markdown bullets with key findings for a tool.
    Any parse error returns an empty list."""
    import json
    import re

    out: list[str] = []
    try:
        if tool == "canvass":
            for sub in subdir.glob("*_subdomains.txt"):
                count = sum(1 for _ in sub.open() if _.strip())
                out.append(f"- subdomains discovered: **{count}**")
                break
            for brief in subdir.glob("*_summary.txt"):
                head = brief.read_text(errors="replace").strip().splitlines()[:20]
                out.append("- top recommendations (from `*_summary.txt`):")
                out.extend(f"  > {l}" for l in head if l.strip())
                break

        elif tool == "nmap":
            for gnmap in subdir.glob("*.gnmap"):
                hosts = 0
                open_ports: dict[str, list[str]] = {}
                for line in gnmap.read_text(errors="replace").splitlines():
                    m = re.match(r"Host: (\S+) .* Ports: (.+?)\tIgnored", line)
                    if not m:
                        continue
                    host, ports_raw = m.group(1), m.group(2)
                    ports = [p.split("/", 1)[0] for p in ports_raw.split(", ") if "/open/" in p]
                    if ports:
                        hosts += 1
                        open_ports[host] = ports
                out.append(f"- hosts with open ports: **{hosts}**")
                for host, ports in list(open_ports.items())[:10]:
                    out.append(f"  - `{host}`: {', '.join(ports)}")
                if len(open_ports) > 10:
                    out.append(f"  - …and {len(open_ports)-10} more")
                break

        elif tool == "httpx":
            for j in subdir.glob("httpx_*.json"):
                urls: list[tuple[str, int]] = []
                for line in j.open():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    u, s = obj.get("url"), obj.get("status_code") or obj.get("status-code")
                    if u:
                        urls.append((u, s or 0))
                out.append(f"- live URLs: **{len(urls)}**")
                for u, s in urls[:15]:
                    out.append(f"  - `{u}` → {s}")
                if len(urls) > 15:
                    out.append(f"  - …and {len(urls)-15} more")
                break

        elif tool == "gowitness":
            screenshots = list((subdir / "screenshots").glob("*.png")) if (subdir / "screenshots").is_dir() else []
            out.append(f"- screenshots captured: **{len(screenshots)}**")

        elif tool == "dig":
            for t in subdir.glob("dig_*.txt"):
                answers = [
                    l for l in t.read_text(errors="replace").splitlines()
                    if l and not l.startswith(";") and "\t" in l
                ]
                if answers:
                    out.append(f"- ANSWER records in `{t.name}`: {len(answers)}")
                break

        elif tool == "trufflehog":
            for t in subdir.glob("trufflehog_*.json"):
                verified = unverified = 0
                for line in t.open():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if obj.get("Verified"):
                        verified += 1
                    elif "DetectorName" in obj:
                        unverified += 1
                out.append(f"- secrets — verified: **{verified}**, unverified: **{unverified}**")
                break

        elif tool == "cloud_enum":
            for t in subdir.glob("cloud_enum_*.txt"):
                hits = [l.strip() for l in t.read_text(errors="replace").splitlines() if "OPEN" in l or "ACCESS" in l]
                out.append(f"- cloud resources of note: **{len(hits)}**")
                for h in hits[:10]:
                    out.append(f"  - {h}")
                if len(hits) > 10:
                    out.append(f"  - …and {len(hits)-10} more")
                break

        elif tool == "s3scanner":
            for t in subdir.glob("s3scanner_*.json"):
                hits = 0
                for line in t.open():
                    try:
                        obj = json.loads(line.strip())
                    except ValueError:
                        continue
                    if obj.get("bucket_exists"):
                        hits += 1
                out.append(f"- buckets confirmed to exist: **{hits}**")
                break

        elif tool == "ffuf":
            for t in subdir.glob("ffuf_*.json"):
                try:
                    obj = json.loads(t.read_text())
                except ValueError:
                    continue
                results = obj.get("results", [])
                out.append(f"- paths found: **{len(results)}**")
                for r in results[:10]:
                    out.append(f"  - `{r.get('url')}` → {r.get('status')}")
                if len(results) > 10:
                    out.append(f"  - …and {len(results)-10} more")
                break

    except (OSError, ValueError):
        return []
    return out


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
        print(f"[+] overwriting existing bundle: {output_path}")
        output_path.unlink()

    all_files = [f for d in detections if d.found for f in d.files]

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / bundle_name
        staging.mkdir()

        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        # Include engagement-level context so the bundle is self-describing.
        eng_root = get_engagement_base() / target
        for name in ("scope.txt", "domains.txt", "notes.md"):
            src = eng_root / name
            if src.is_file():
                shutil.copy2(src, staging / name)

        # Generate an LLM-friendly summary with signal extracted from each tool.
        summary = build_summary(target, etype, date_stamp, detections, eng_root)
        (staging / "summary.md").write_text(summary, encoding="utf-8")

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
        tgt = prompted["target"]
        return preset + (["-iL", tgt] if Path(tgt).is_file() else [tgt])
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


def scope_path_for(target: str) -> Path:
    return get_engagement_base() / target / "scope.txt"


def notes_path_for(target: str) -> Path:
    return get_engagement_base() / target / "notes.md"


def domains_path_for(target: str) -> Path:
    return get_engagement_base() / target / "domains.txt"


def read_domains(target: str) -> list[str]:
    """Return non-empty, non-comment lines from domains.txt. Empty list if missing."""
    f = domains_path_for(target)
    if not f.is_file():
        return []
    return [
        line.strip() for line in f.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _canvass_brief_for(target: str, etype: str, domain: str) -> Path | None:
    """Return the canvass brief path for a specific domain, or None if absent."""
    recon = get_engagement_base() / target / etype / "recon"
    safe = domain.replace(".", "_")
    for ext in ("txt", "md"):
        p = recon / f"{safe}_brief.{ext}"
        if p.exists():
            return p
    return None


def canvass_missing_domains(target: str, etype: str) -> list[str]:
    """Subset of domains.txt entries that don't yet have a canvass brief."""
    return [d for d in read_domains(target) if _canvass_brief_for(target, etype, d) is None]


def aggregate_subdomains(target: str, etype: str) -> Path | None:
    """Concat + dedupe every *_subdomains.txt in ext/recon/ into one file
    under ~/engagements/<target>/.aggregates/ (outside ext/ so collectors ignore it).
    Returns the aggregate path, or None if there are no subdomain files.
    """
    recon = get_engagement_base() / target / etype / "recon"
    if not recon.is_dir():
        return None
    files = sorted(recon.glob("*_subdomains.txt"))
    if not files:
        return None
    agg_dir = get_engagement_base() / target / ".aggregates"
    agg_dir.mkdir(parents=True, exist_ok=True)
    out = agg_dir / f"{etype}_httpx_input.txt"
    seen: set[str] = set()
    with out.open("w") as w:
        for f in files:
            for line in f.read_text(errors="replace").splitlines():
                host = line.strip()
                if host and host not in seen:
                    seen.add(host)
                    w.write(host + "\n")
    return out


def _open_in_editor(path: Path, template: str) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(template)

    editor = os.environ.get("EDITOR")
    for candidate in [editor, "nano", "vi"]:
        if candidate and subprocess.run(["which", candidate], capture_output=True).returncode == 0:
            subprocess.run([candidate, str(path)])
            print(f"[+] saved: {path}")
            return 0

    print(f"error: no editor found (tried $EDITOR, nano, vi). edit manually: {path}", file=sys.stderr)
    return 1


def cmd_domains(args) -> int:
    target = read_engagement_file()
    if not target:
        print("error: no active engagement. run 'rpt new <target>' or 'rpt use <target>' first.", file=sys.stderr)
        return 1

    template = (
        f"# root domains for engagement: {target}\n"
        "# one root domain per line — canvass will run once per domain\n"
        "# lines starting with '#' are ignored\n"
        "# example:\n"
        "# example.com\n"
        "# example.io\n"
    )
    return _open_in_editor(domains_path_for(target), template)


def cmd_notes(args) -> int:
    target = read_engagement_file()
    if not target:
        print("error: no active engagement. run 'rpt new <target>' or 'rpt use <target>' first.", file=sys.stderr)
        return 1

    template = (
        f"# notes for engagement: {target}\n\n"
        "## objectives\n\n"
        "- \n\n"
        "## out-of-scope\n\n"
        "- \n\n"
        "## findings / leads\n\n"
        "- \n"
    )
    return _open_in_editor(notes_path_for(target), template)


def cmd_scope(args) -> int:
    target = read_engagement_file()
    if not target:
        print("error: no active engagement. run 'rpt new <target>' or 'rpt use <target>' first.", file=sys.stderr)
        return 1

    template = (
        f"# scope for engagement: {target}\n"
        "# one target per line — IPs, CIDRs, hostnames all work\n"
        "# lines starting with '#' are ignored by most tools\n"
        "# example:\n"
        "# 192.0.2.10\n"
        "# 198.51.100.0/24\n"
        "# host.example.com\n"
    )
    return _open_in_editor(scope_path_for(target), template)


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


def tool_has_output(tool: str, target: str, etype: str) -> bool:
    """True if the tool's engagement subdir has any non-hidden output file."""
    subdir = TOOL_SUBDIR_MAP.get(tool)
    if not subdir:
        return False
    path = get_engagement_base() / target / etype / subdir
    if not path.is_dir():
        return False
    return any(p.is_file() and not p.name.startswith(".") for p in path.rglob("*"))


def show_phase_status(phase: str, tools: list[str], target: str, etype: str) -> None:
    """Print a [x]/[ ] checklist of which tools in the phase have produced output."""
    done = [t for t in tools if tool_has_output(t, target, etype)]
    todo = [t for t in tools if t not in done]

    print(f"\n{phase} phase status:")
    for t in tools:
        mark = "[x]" if t in done else "[ ]"
        print(f"  {mark} {t}")

    print()
    if not todo:
        print("all tools in this phase have output.")
    else:
        print(f"{len(todo)}/{len(tools)} still need to run: {', '.join(todo)}")
        print("run the tools manually, or use `rpt run -p auto` for the full chain.")


CHAIN_MARKER = "__CHAIN__"

CHAINABLE_INPUTS = {
    ("httpx", "input"),      # chains from canvass subdomains
    ("gowitness", "input"),  # chains from httpx urls
}


def gather_auto_inputs(tools: list[str], target: str, etype: str) -> dict | None:
    """Prompt for every input needed by every tool in auto phase, upfront.

    Chainable inputs (httpx input from canvass, gowitness input from httpx) are
    stored as CHAIN_MARKER and resolved at runtime when the previous tool's
    output exists. Returns None if aborted.
    """
    print("\ngathering inputs upfront — answer once, then walk away.")
    print("press Enter to accept [default]; blank with no default = skip that tool.\n")

    collected: dict[str, dict | None] = {}
    domains_list = read_domains(target)

    for tool in tools:
        prompts = TOOL_PROMPTS.get(tool, [])

        # Canvass gets special handling when domains.txt is populated:
        # it iterates per domain at run time instead of prompting for one.
        if tool == "canvass" and domains_list:
            missing = canvass_missing_domains(target, etype)
            if not missing:
                print(f"[canvass] all {len(domains_list)} domain(s) from domains.txt already scanned — will skip\n")
                collected[tool] = None
            else:
                print(f"[canvass] {len(missing)}/{len(domains_list)} domain(s) still to scan: {', '.join(missing)}\n")
                collected[tool] = {"_from_domains_file": True}
            continue

        # Skip prompts entirely for tools that already have output (resumable).
        if tool_has_output(tool, target, etype):
            print(f"[{tool}] already has output — will skip at run time\n")
            collected[tool] = None
            continue

        if not prompts:
            collected[tool] = {}
            continue

        print(f"[{tool}]")
        tool_inputs: dict[str, str] = {}
        skipped = False
        for prompt_text, key in prompts:
            default = prompt_default(tool, key, target, etype, context=collected)
            chainable = (tool, key) in CHAINABLE_INPUTS

            if chainable and not default:
                label = " [auto — chains from previous tool]"
            elif default:
                label = f" [{default}]"
            else:
                label = ""

            try:
                value = input(f"  {prompt_text}{label}: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\naborted.", file=sys.stderr)
                return None

            if not value:
                if default:
                    tool_inputs[key] = default
                elif chainable:
                    tool_inputs[key] = CHAIN_MARKER
                else:
                    print(f"  -> will skip {tool} (no input provided)")
                    skipped = True
                    break
            else:
                tool_inputs[key] = value

        collected[tool] = None if skipped else tool_inputs
        print()

    return collected


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
    print(f"output:  ~/engagements/{target}/{etype}/")

    # Non-auto phases are status-only — never execute anything.
    # Only `-p auto` actually runs tools.
    if phase != "auto":
        show_phase_status(phase, tools, target, etype)
        return 0

    # Collect every tool's inputs upfront so the operator can walk away
    # during the actual execution.
    collected = gather_auto_inputs(tools, target, etype)
    if collected is None:
        return 1

    print("\n" + "─" * 50)
    print("all inputs collected. starting auto run.")
    print("─" * 50 + "\n")

    succeeded = []
    failed = []
    skipped = []
    bin_dir = Path.home() / "bin"

    for i, tool in enumerate(tools, 1):
        print(f"[{i}/{len(tools)}] {tool}")

        prompted = collected.get(tool)

        # Multi-domain canvass path: iterate domains.txt entries that don't
        # yet have a brief file, run canvass once per missing domain.
        if tool == "canvass" and isinstance(prompted, dict) and prompted.get("_from_domains_file"):
            missing = canvass_missing_domains(target, etype)
            if not missing:
                print("  ✓ all domains already scanned — skipping")
                succeeded.append(tool)
                print()
                continue
            wrapper = bin_dir / tool
            env = os.environ.copy()
            env["ENGAGEMENT_TYPE"] = etype
            all_ok = True
            for d in missing:
                print(f"  [canvass → {d}] running...")
                rc = subprocess.run(
                    [str(wrapper)] + build_tool_args("canvass", {"domain": d}, target),
                    env=env, stdin=subprocess.DEVNULL,
                ).returncode
                if rc == 0:
                    print(f"  ✓ canvass {d} done")
                else:
                    print(f"  ! canvass {d} exited {rc}")
                    all_ok = False
            (succeeded if all_ok else failed).append(tool)
            print()
            continue

        if prompted is None:
            # Either already has output (resume) or operator left required input blank upfront.
            if tool_has_output(tool, target, etype):
                print(f"  ✓ already has output — skipping (delete {TOOL_SUBDIR_MAP[tool]}/ to re-run)")
                succeeded.append(tool)
            else:
                print("  -> skipping (no input provided upfront)")
                skipped.append(tool)
            print()
            continue

        # Resolve any deferred chain markers now — previous tool may have produced output.
        resolved: dict[str, str] = {}
        chain_missing = False
        for key, value in prompted.items():
            if value == CHAIN_MARKER:
                fresh = prompt_default(tool, key, target, etype)
                if not fresh:
                    chain_missing = True
                    break
                resolved[key] = fresh
                print(f"  chained {key} -> {fresh}")
            else:
                resolved[key] = value

        if chain_missing:
            print("  -> skipping (previous tool produced no output to chain from)")
            skipped.append(tool)
            print()
            continue

        tool_args = build_tool_args(tool, resolved, target)
        wrapper = bin_dir / tool

        if not wrapper.exists():
            print(f"  warning: wrapper not found at {wrapper}. skipping.")
            failed.append(tool)
            print()
            continue

        env = os.environ.copy()
        env["ENGAGEMENT_TYPE"] = etype

        print(f"  running {tool}...")
        result = subprocess.run([str(wrapper)] + tool_args, env=env, stdin=subprocess.DEVNULL)

        if result.returncode == 0:
            print(f"  ✓ {tool} done")
            succeeded.append(tool)
        else:
            print(f"  ! {tool} exited {result.returncode} — continuing")
            failed.append(tool)

        print()

    print(f"✓ auto run complete: {len(succeeded)}/{len(tools)} tools succeeded")
    if skipped:
        print(f"  skipped:        {', '.join(skipped)}")
    if failed:
        print(f"  failed:         {', '.join(failed)}")
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
    new_p.add_argument("target", help="target name (e.g. examplecorp)")

    use_p = subparsers.add_parser("use", help="switch to an existing engagement")
    use_p.add_argument("target", help="target name")

    subparsers.add_parser("current", help="print the active engagement")
    subparsers.add_parser("list", help="list all engagements")
    subparsers.add_parser("scope", help="edit scope.txt for the active engagement ($EDITOR / nano / vi)")
    subparsers.add_parser("domains", help="edit domains.txt (root domains canvass iterates over)")
    subparsers.add_parser("notes", help="edit notes.md for the active engagement")

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
        "scope": cmd_scope,
        "domains": cmd_domains,
        "notes": cmd_notes,
        "run": cmd_run,
        "collect": cmd_collect,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
