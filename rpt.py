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
    "recon":    ["canvass", "uncover", "dnstwist", "cloud-enum"],
    "dns":      ["dig", "dnsx"],
    "scanning": ["naabu", "nmap", "httpx", "gowitness"],
    "web":      ["urlfinder", "katana", "ffuf"],
    "vuln":     ["nuclei"],
    # auto: full external pipeline. Phase 1 -> 7. Hands-off after upfront prompts.
    # Excludes auth-gated/source-specific tools (roadtools, teamfiltration,
    # trufflehog, s3scanner) — those stay manual.
    "auto":     ["canvass", "uncover", "dnstwist", "cloud-enum",
                 "dnsx",
                 "naabu", "nmap",
                 "httpx", "gowitness",
                 "urlfinder", "katana", "ffuf",
                 "nuclei"],
}

# Tools that hard-stop the auto chain on failure — downstream literally can't
# function without their output.
CRITICAL_TOOLS = {"canvass", "dnsx", "httpx"}

FFUF_DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

TOOL_PROMPTS = {
    "canvass":        [("root domain (e.g. example.com)", "domain")],
    "cloud-enum":     [("keywords, comma-separated (e.g. example,examplecorp,example-prod)", "keywords")],
    "uncover":        [("query (e.g. ssl:\"example\" or org:\"Example Corp\")", "query")],
    "dnstwist":       [("domain to permute", "domain")],
    "dnsx":           [("input (subdomains list file or single host) — Enter to auto-chain", "input")],
    "naabu":          [("target (scope file or single IP/CIDR) — Enter to auto-chain", "target")],
    "nmap":           [("target (scope file path preferred, or single IP/CIDR/hostname)", "target"),
                       ("scan type (quick/full/udp/service)", "scan_type")],
    "httpx":          [("host list file (from canvass subdomains) — Enter to auto-chain", "input")],
    "gowitness":      [("URL list file (from httpx) — Enter to auto-chain", "input")],
    "urlfinder":      [("input (URL list or single URL) — Enter to auto-chain", "input")],
    "katana":         [("input (URL list or single URL) — Enter to auto-chain", "input")],
    "nuclei":         [("input (URL list file or single URL) — Enter to auto-chain", "input")],
    "dig":            [("domain", "domain"),
                       ("record type (A/MX/TXT/NS/ANY)", "record_type")],
    "ffuf":           [("target URL (MUST include FUZZ placeholder, e.g. https://example.com/FUZZ)", "url"),
                       ("wordlist path", "wordlist")],
    "roadtools":      [("auth method (devicecode/password/token)", "auth_method")],
    "s3scanner":      [("bucket names file path OR single bucket keyword", "input")],
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
    "recon", "uncover", "dnstwist", "trufflehog",
    "cloud", "roadtools", "s3scanner",
    "dns", "dnsx",
    "naabu", "nmap", "httpx", "gowitness",
    "urlfinder", "katana", "ffuf",
    "nuclei",
    "spray",
]

TOOL_SUBDIR_MAP = {
    "canvass":        "recon",
    "cloud-enum":     "cloud",
    "uncover":        "uncover",
    "dnstwist":       "dnstwist",
    "trufflehog":     "trufflehog",
    "roadtools":      "roadtools",
    "s3scanner":      "s3scanner",
    "dig":            "dns",
    "dnsx":           "dnsx",
    "naabu":          "naabu",
    "nmap":           "nmap",
    "httpx":          "httpx",
    "gowitness":      "gowitness",
    "urlfinder":      "urlfinder",
    "katana":         "katana",
    "ffuf":           "ffuf",
    "nuclei":         "nuclei",
    "teamfiltration": "spray",
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

    Chain map for the auto pipeline:
      dnsx input        ← canvass+uncover subdomain union (or scope.txt)
      naabu target      ← dnsx live hosts (or scope.txt)
      httpx input       ← canvass subdomains aggregate (or dnsx live hosts, or scope.txt)
      gowitness input   ← httpx urls.txt
      urlfinder input   ← httpx urls.txt
      katana input      ← httpx urls.txt
      nuclei input      ← phase-5 URL union (urlfinder + katana + ffuf + httpx)
      nmap target       ← scope.txt
      nmap scan_type    ← "quick"
      dig record_type   ← "A"
      ffuf url          ← https://<primary>/FUZZ  (primary = domains.txt[0] | canvass.domain | target)
      ffuf wordlist     ← first existing FFUF_DEFAULT_WORDLISTS entry
    """
    base = get_engagement_base() / target

    def _scope_clean() -> str | None:
        """Returns a path to a comment-stripped scope.txt, or None."""
        cs = clean_scope_path(target)
        return str(cs) if cs else None

    def _newest(glob_path: Path, pattern: str) -> Path | None:
        if not glob_path.is_dir():
            return None
        matches = sorted(glob_path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        return matches[0] if matches else None

    if tool == "nmap" and key == "target":
        s = _scope_clean()
        if s:
            return s
    if tool == "nmap" and key == "scan_type":
        return "quick"
    if tool == "dig" and key == "record_type":
        return "A"

    # dnsx: union of canvass subdomain lists (multi-domain aggregate) → scope.txt
    if tool == "dnsx" and key == "input":
        recon = base / etype / "recon"
        if recon.is_dir() and list(recon.glob("*_subdomains.txt")):
            agg = aggregate_subdomains(target, etype)
            if agg:
                return str(agg)
        return _scope_clean()

    # naabu: dnsx live hosts → scope.txt
    if tool == "naabu" and key == "target":
        live_hosts = aggregate_dnsx_hosts(target, etype)
        if live_hosts:
            return str(live_hosts)
        return _scope_clean()

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
        # Fallback: dnsx live host list
        live_hosts = aggregate_dnsx_hosts(target, etype)
        if live_hosts:
            return str(live_hosts)
        return _scope_clean()

    if tool == "gowitness" and key == "input":
        urls = _newest(base / etype / "httpx", "*_urls.txt")
        if urls:
            return str(urls)
        return _scope_clean()

    # urlfinder + katana: same chain as gowitness — feed httpx URL list.
    if tool in ("urlfinder", "katana") and key == "input":
        urls = _newest(base / etype / "httpx", "*_urls.txt")
        if urls:
            return str(urls)
        return _scope_clean()

    # nuclei: aggregate of phase-5 URL discovery + httpx live URLs.
    if tool == "nuclei" and key == "input":
        agg = aggregate_phase5_urls(target, etype)
        if agg:
            return str(agg)
        urls = _newest(base / etype / "httpx", "*_urls.txt")
        if urls:
            return str(urls)
        return _scope_clean()

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
                    # Preserve any subdir hierarchy below mod.SUBDIR (e.g. gowitness/screenshots/foo.jpeg)
                    rel = match.relative_to(subdir_path)
                    dest = f"{mod.SUBDIR}/{rel}"
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
            shot_dir = subdir / "screenshots"
            shots = (
                list(shot_dir.glob("*.jpeg")) + list(shot_dir.glob("*.jpg")) + list(shot_dir.glob("*.png"))
                if shot_dir.is_dir() else []
            )
            out.append(f"- screenshots captured: **{len(shots)}**")

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
                hits = [
                    l.strip() for l in t.read_text(errors="replace").splitlines()
                    if "OPEN" in l or "HTTP-OK" in l or "[+]" in l
                ]
                out.append(f"- cloud assets discovered: **{len(hits)}**")
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

        elif tool == "nuclei":
            for t in subdir.glob("nuclei_*.json"):
                by_sev: dict[str, int] = {}
                top: list[tuple[str, str, str]] = []  # (severity, template, host)
                for line in t.open():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    sev = (obj.get("info", {}) or {}).get("severity", "info").lower()
                    by_sev[sev] = by_sev.get(sev, 0) + 1
                    if sev in ("critical", "high"):
                        top.append((sev, obj.get("template-id", ""), obj.get("matched-at", "")))
                total = sum(by_sev.values())
                out.append(f"- findings: **{total}** total — " + ", ".join(
                    f"{k}: {by_sev[k]}" for k in ("critical", "high", "medium", "low", "info") if k in by_sev
                ))
                for sev, tpl, host in top[:10]:
                    out.append(f"  - [{sev.upper()}] `{tpl}` @ {host}")
                if len(top) > 10:
                    out.append(f"  - …and {len(top)-10} more critical/high")
                break

        elif tool == "naabu":
            for t in subdir.glob("naabu_*.json"):
                hosts: dict[str, list[int]] = {}
                for line in t.open():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    h, p = obj.get("host") or obj.get("ip"), obj.get("port")
                    if h and p:
                        hosts.setdefault(h, []).append(p)
                total_ports = sum(len(v) for v in hosts.values())
                out.append(f"- hosts with open ports: **{len(hosts)}**, total open ports: **{total_ports}**")
                for h, ports in list(hosts.items())[:10]:
                    out.append(f"  - `{h}`: {', '.join(map(str, sorted(set(ports))))}")
                if len(hosts) > 10:
                    out.append(f"  - …and {len(hosts)-10} more")
                break

        elif tool == "katana":
            for t in subdir.glob("katana_*.jsonl"):
                count = sum(1 for line in t.open() if line.strip())
                out.append(f"- endpoints crawled: **{count}**")
                break

        elif tool == "urlfinder":
            for t in subdir.glob("urlfinder_*.txt"):
                count = sum(1 for line in t.open() if line.strip())
                out.append(f"- archive URLs surfaced: **{count}**")
                break

        elif tool == "dnsx":
            for t in subdir.glob("dnsx_*.json"):
                hosts = 0
                for line in t.open():
                    line = line.strip()
                    if line:
                        hosts += 1
                out.append(f"- hosts resolved: **{hosts}**")
                break

        elif tool == "uncover":
            for t in subdir.glob("uncover_*.json"):
                hits = sum(1 for line in t.open() if line.strip())
                out.append(f"- assets surfaced: **{hits}**")
                break

        elif tool == "dnstwist":
            registered = 0
            files = 0
            for t in subdir.glob("dnstwist_*_*.json"):
                files += 1
                try:
                    data = json.loads(t.read_text(errors="replace"))
                except ValueError:
                    continue
                # dnstwist json: list of permutation dicts; "dns_a" key => registered
                if isinstance(data, list):
                    for item in data:
                        if item.get("dns_a") or item.get("dns_aaaa") or item.get("dns_mx"):
                            registered += 1
            out.append(f"- domains permuted across **{files}** root(s); **{registered}** typosquats currently resolve")

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
    elif tool == "uncover":
        return ["-q", prompted["query"]]
    elif tool == "dnstwist":
        return [prompted["domain"]]
    elif tool == "dnsx":
        inp = prompted["input"]
        # dnsx can take -l <file> for list or -d <domain> for single host.
        return ["-l", inp] if Path(inp).is_file() else ["-d", inp]
    elif tool == "naabu":
        tgt = prompted["target"]
        return ["-list", tgt] if Path(tgt).is_file() else ["-host", tgt]
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
    elif tool == "urlfinder":
        inp = prompted["input"]
        return ["-list", inp] if Path(inp).is_file() else ["-d", inp]
    elif tool == "katana":
        inp = prompted["input"]
        return ["-list", inp] if Path(inp).is_file() else ["-u", inp]
    elif tool == "nuclei":
        inp = prompted["input"]
        return ["-l", inp] if Path(inp).is_file() else ["-u", inp]
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


def _dnstwist_output_for(target: str, etype: str, domain: str) -> Path | None:
    """Return the latest dnstwist json for a specific domain, or None if absent."""
    dt_dir = get_engagement_base() / target / etype / "dnstwist"
    if not dt_dir.is_dir():
        return None
    safe = domain.replace(".", "_")
    matches = list(dt_dir.glob(f"dnstwist_{safe}_*.json"))
    return matches[0] if matches else None


# Tools that iterate per-domain rather than aggregate.
PER_DOMAIN_TOOLS = {
    "canvass":  _canvass_brief_for,
    "dnstwist": _dnstwist_output_for,
}


def missing_domains_for(tool: str, target: str, etype: str) -> list[str]:
    """For a per-domain tool, the subset of domains.txt entries that don't yet
    have output for that tool."""
    fn = PER_DOMAIN_TOOLS.get(tool)
    if fn is None:
        return []
    return [d for d in read_domains(target) if fn(target, etype, d) is None]


def canvass_missing_domains(target: str, etype: str) -> list[str]:
    """Backward-compat wrapper around missing_domains_for('canvass', ...)."""
    return missing_domains_for("canvass", target, etype)


def _aggregates_dir(target: str) -> Path:
    """~/engagements/<target>/.aggregates/ — chain inputs live here, outside ext/
    so collectors don't sweep them into bundles."""
    d = get_engagement_base() / target / ".aggregates"
    d.mkdir(parents=True, exist_ok=True)
    return d


def clean_scope_path(target: str) -> Path | None:
    """Produce a comment-free copy of scope.txt at .aggregates/scope_clean.txt.
    Tools like dnsx/naabu/urlfinder don't strip '#' lines, so we hand them a
    pre-cleaned file. Returns None if scope.txt is missing or empty after strip.
    """
    src = get_engagement_base() / target / "scope.txt"
    if not src.is_file():
        return None
    clean_lines = [
        l.strip() for l in src.read_text(errors="replace").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]
    if not clean_lines:
        return None
    out = _aggregates_dir(target) / "scope_clean.txt"
    out.write_text("\n".join(clean_lines) + "\n")
    return out


def _canvass_cloud_hosts(target: str, etype: str) -> set[str]:
    """Extract hostnames from canvass cloud-raw.json so cloud-discovered
    Azure Blob/Files/SharePoint/etc. endpoints flow through the chain
    (dnsx → httpx → nuclei) instead of just sitting as findings."""
    import json as _json
    cloud_json = get_engagement_base() / target / etype / "recon" / "cloud-raw.json"
    if not cloud_json.is_file():
        return set()
    try:
        data = _json.loads(cloud_json.read_text(errors="replace"))
    except (ValueError, OSError):
        return set()

    hosts: set[str] = set()

    def _harvest(obj):
        """Walk arbitrary canvass JSON shapes pulling out any hostname-like values."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and k in ("hostname", "host", "target", "fqdn", "domain", "url"):
                    h = v.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                    if "." in h and not h.startswith("#"):
                        hosts.add(h)
                else:
                    _harvest(v)
        elif isinstance(obj, list):
            for item in obj:
                _harvest(item)

    _harvest(data)
    return hosts


def _cloud_enum_hosts(target: str, etype: str) -> set[str]:
    """Extract hostnames from cloud_enum text output (lines starting with
    e.g. '[+] OPEN: https://foo.s3.amazonaws.com/' or '[!] HTTP-OK: ...')."""
    import re as _re
    cloud_dir = get_engagement_base() / target / etype / "cloud"
    if not cloud_dir.is_dir():
        return set()
    hosts: set[str] = set()
    url_re = _re.compile(r"https?://([a-zA-Z0-9_.-]+)")
    bare_re = _re.compile(r"\b([a-zA-Z0-9_-]+\.(?:s3|blob|file|queue|table|storage|appspot|web)\.[a-zA-Z0-9_.-]+)\b")
    for f in cloud_dir.glob("cloud_enum_*.txt"):
        for line in f.read_text(errors="replace").splitlines():
            for m in url_re.findall(line):
                hosts.add(m.split(":", 1)[0])
            for m in bare_re.findall(line):
                hosts.add(m)
    # Strip trailing slashes / paths defensively
    return {h.rstrip("/") for h in hosts if "." in h}


def aggregate_subdomains(target: str, etype: str) -> Path | None:
    """Concat + dedupe every <recon>/*_subdomains.txt PLUS canvass-discovered
    cloud hostnames PLUS cloud_enum-discovered cloud hostnames into one file.
    Returns the aggregate path, or None if nothing to aggregate.
    """
    recon = get_engagement_base() / target / etype / "recon"
    if not recon.is_dir():
        return None
    files = sorted(recon.glob("*_subdomains.txt"))
    cloud_hosts = _canvass_cloud_hosts(target, etype) | _cloud_enum_hosts(target, etype)
    if not files and not cloud_hosts:
        return None
    out = _aggregates_dir(target) / f"{etype}_subdomains.txt"
    seen: set[str] = set()
    with out.open("w") as w:
        for f in files:
            for line in f.read_text(errors="replace").splitlines():
                host = line.strip()
                if not host or host.startswith("#"):
                    continue
                if host not in seen:
                    seen.add(host)
                    w.write(host + "\n")
        for host in sorted(cloud_hosts):
            if host not in seen:
                seen.add(host)
                w.write(host + "\n")
    return out


def aggregate_dnsx_hosts(target: str, etype: str) -> Path | None:
    """Extract live hostnames + IPs from the newest dnsx_*.json output, dedupe.
    dnsx writes JSONL with `host` and `a` (or other record) fields per line.
    """
    import json as _json
    dnsx_dir = get_engagement_base() / target / etype / "dnsx"
    if not dnsx_dir.is_dir():
        return None
    files = sorted(dnsx_dir.glob("dnsx_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None
    src = files[0]
    out = _aggregates_dir(target) / f"{etype}_dnsx_hosts.txt"
    seen: set[str] = set()
    with out.open("w") as w:
        for line in src.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except ValueError:
                continue
            host = obj.get("host")
            if not host or host.startswith("#"):
                continue
            # Skip NXDOMAIN entries — only emit hosts that actually resolved.
            status = obj.get("status_code") or obj.get("status_code_raw")
            if status in ("NXDOMAIN", 3):
                continue
            if host not in seen:
                seen.add(host)
                w.write(host + "\n")
    return out if seen else None


def aggregate_phase5_urls(target: str, etype: str) -> Path | None:
    """Concat + dedupe URLs from urlfinder/katana/ffuf/httpx outputs into one
    URL-per-line file for nuclei input."""
    import json as _json
    base = get_engagement_base() / target / etype
    out = _aggregates_dir(target) / f"{etype}_phase5_urls.txt"
    seen: set[str] = set()

    def _add(u: str) -> None:
        u = (u or "").strip()
        if u and u not in seen:
            seen.add(u)

    # urlfinder: plain text, one URL per line
    uf_dir = base / "urlfinder"
    if uf_dir.is_dir():
        for f in uf_dir.glob("urlfinder_*.txt"):
            for line in f.read_text(errors="replace").splitlines():
                _add(line)

    # katana: JSONL, "request.url" or top-level "url"
    kt_dir = base / "katana"
    if kt_dir.is_dir():
        for f in kt_dir.glob("katana_*.jsonl"):
            for line in f.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                except ValueError:
                    continue
                _add(obj.get("request", {}).get("endpoint") if isinstance(obj.get("request"), dict) else None)
                _add(obj.get("url"))

    # ffuf: single JSON with results[]
    ff_dir = base / "ffuf"
    if ff_dir.is_dir():
        for f in ff_dir.glob("ffuf_*.json"):
            try:
                obj = _json.loads(f.read_text(errors="replace"))
            except ValueError:
                continue
            for r in obj.get("results", []) or []:
                _add(r.get("url"))

    # httpx: JSONL, "url" field — included so nuclei has at least the live set
    hx_dir = base / "httpx"
    if hx_dir.is_dir():
        for f in hx_dir.glob("httpx_*_urls.txt"):
            for line in f.read_text(errors="replace").splitlines():
                _add(line)

    if not seen:
        return None
    out.write_text("\n".join(sorted(seen)) + "\n")
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


def cmd_update(args) -> int:
    """Re-run repkit/install.sh — upgrades every Go tool to @latest, pulls
    latest for git clones, refreshes pip packages, re-fetches nuclei templates.
    """
    install_sh = Path(__file__).resolve().parent / "repkit" / "install.sh"
    if not install_sh.is_file():
        print(f"error: install script not found at {install_sh}", file=sys.stderr)
        return 1
    print("[+] running repkit/install.sh to refresh all tools...")
    return subprocess.run(["bash", str(install_sh)]).returncode


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
    ("dnsx", "input"),         # from canvass+uncover subdomain union
    ("naabu", "target"),       # from dnsx live IPs
    ("httpx", "input"),        # from canvass subdomains (or dnsx live hosts)
    ("gowitness", "input"),    # from httpx urls
    ("urlfinder", "input"),    # from httpx urls
    ("katana", "input"),       # from httpx urls
    ("nuclei", "input"),       # from union of urlfinder/katana/ffuf/httpx
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

        # Per-domain tools (canvass, dnstwist) iterate domains.txt at run time
        # instead of prompting for a single domain.
        if tool in PER_DOMAIN_TOOLS and domains_list:
            missing = missing_domains_for(tool, target, etype)
            if not missing:
                print(f"[{tool}] all {len(domains_list)} domain(s) from domains.txt already done — will skip\n")
                collected[tool] = None
            else:
                print(f"[{tool}] {len(missing)}/{len(domains_list)} domain(s) still to do: {', '.join(missing)}\n")
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

        # Per-domain iteration (canvass, dnstwist).
        if tool in PER_DOMAIN_TOOLS and isinstance(prompted, dict) and prompted.get("_from_domains_file"):
            missing = missing_domains_for(tool, target, etype)
            if not missing:
                print(f"  ✓ all domains already done — skipping")
                succeeded.append(tool)
                print()
                continue
            wrapper = bin_dir / tool
            env = os.environ.copy()
            env["ENGAGEMENT_TYPE"] = etype
            all_ok = True
            for d in missing:
                print(f"  [{tool} → {d}] running...")
                # Both canvass and dnstwist take the domain as the sole arg.
                rc = subprocess.run(
                    [str(wrapper)] + build_tool_args(tool, {"domain": d}, target),
                    env=env, stdin=subprocess.DEVNULL,
                ).returncode
                if rc == 0:
                    print(f"  ✓ {tool} {d} done")
                else:
                    print(f"  ! {tool} {d} exited {rc}")
                    all_ok = False
            if all_ok:
                succeeded.append(tool)
            else:
                failed.append(tool)
                if tool in CRITICAL_TOOLS:
                    print(f"  ✗ {tool} CRITICAL — aborting chain")
                    return 1
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
            failed.append(tool)
            if tool in CRITICAL_TOOLS:
                print(f"  ✗ {tool} exited {result.returncode} — CRITICAL TOOL FAILED, aborting chain")
                print(f"    (downstream tools depend on {tool} output; fix and re-run)")
                print()
                print(f"✗ auto run aborted: {len(succeeded)}/{len(tools)} succeeded before failure")
                if skipped:
                    print(f"  skipped: {', '.join(skipped)}")
                print(f"  failed:  {', '.join(failed)}")
                return 1
            print(f"  ! {tool} exited {result.returncode} — continuing (non-critical)")

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
    subparsers.add_parser("update", help="upgrade every installed tool to its latest version")

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
        "update": cmd_update,
        "run": cmd_run,
        "collect": cmd_collect,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
