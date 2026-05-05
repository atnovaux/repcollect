# repcollect

Two-tool red team kit for Kali engagement boxes:

- **`rpt`** — operator CLI. Manages engagements, orchestrates a 13-tool external pipeline, bundles output for reptr / LLM analysis.
- **`repkit/`** — installs every tool and ships a bash wrapper per tool that forces output into the engagement directory regardless of what flags the operator passes. Output organization is structurally enforced.

## Install

```bash
git clone <repo>
cd repcollect
./install.sh
source ~/.zshrc
```

Requires Python 3.10+, Kali Linux, runs as root, zsh-only. First install pulls dotnet (for TeamFiltration) and clones nuclei templates — budget ~15 min.

## Engagement workflow

```bash
rpt new example.com                 # one engagement = one client
rpt use example.com
rpt scope                           # paste in-scope IPs/hosts in $EDITOR
rpt domains                         # paste root domains (one per line)
rpt notes                           # (optional) objectives, leads
rpt run -t ext -p auto              # walk away ~10-20 min
rpt collect -t ext                  # bundle for handoff
```

`rpt run -t ext -p auto` collects every needed input upfront (canvass auto-iterates `domains.txt`, cloud-enum keywords, optional uncover query), then executes hands-off.

**Re-running `auto` is idempotent.** Tools that already have output skip. Adding a new domain to `domains.txt` and re-running only scans the new domain.

```bash
rpt list                            # all engagements (* = active)
rpt use <other>                     # switch
rpt current                         # print active
rpt update                          # weekly: upgrade all tools + nuclei templates
```

## Pipeline (`rpt run -t ext -p auto`)

Each phase chains into the next:

| # | Tool | Output | Chains to |
|---|---|---|---|
| 1 | **canvass** | `recon/<domain>_brief.md`, subdomains, cloud assets | dnsx, httpx |
| 2 | **uncover** | `uncover/uncover_*.json` (Shodan/Censys/FOFA) | (skipped without API keys) |
| 3 | **dnstwist** | `dnstwist/dnstwist_<domain>_*.json` typosquats | (standalone) |
| 4 | **cloud_enum** | `cloud/cloud_enum_*.txt` AWS/Azure/GCP brute-force | dnsx, httpx |
| 5 | **dnsx** | `dnsx/dnsx_*.json` resolved hosts | naabu, httpx |
| 6 | **naabu** | `naabu/naabu_*.json` open ports | nmap |
| 7 | **nmap** | `nmap/nmap_*.{nmap,xml,gnmap}` services + NSE | reptr |
| 8 | **httpx** | `httpx/httpx_*.json` + `httpx_*_urls.txt` | gowitness, urlfinder, katana, nuclei |
| 9 | **gowitness** | `gowitness/screenshots/*.jpeg` + sqlite/jsonl | reptr |
| 10 | **urlfinder** | `urlfinder/urlfinder_*.txt` archive URLs | nuclei |
| 11 | **katana** | `katana/katana_*.jsonl` JS-spider URLs | nuclei |
| 12 | **ffuf** | `ffuf/ffuf_*.json` brute-forced paths | nuclei |
| 13 | **nuclei** | `nuclei/nuclei_*.json` findings | reptr |

**Failure policy:** `canvass` / `dnsx` / `httpx` are critical — failure aborts the chain. All others continue on failure.

**Per-phase status view** (no execution): `rpt run -t ext -p <phase>` for any non-`auto` phase prints a `[x]/[ ]` checklist of what's done in that phase.

## Manual tools (run when relevant — output auto-deposits to engagement)

| Tool | When | Example |
|---|---|---|
| **trufflehog** | After finding a GitHub org or git repo | `trufflehog github --org=example` |
| **teamfiltration** | M365 enum/spray after canvass confirms tenant | `teamfiltration --enum --tenant-info --domain example.com` |
| **roadtools** | Post-creds Entra ID exploration | `roadtools roadrecon gather --devicecode` |
| **s3scanner** | Specific bucket testing | `s3scanner -bucket example` |
| **dig** | Ad-hoc DNS lookups | `dig example.com ANY` |

All wrappers default to `ENGAGEMENT_TYPE=ext`, so output lands at `~/engagements/<target>/ext/<tool>/`. No env vars needed.

## Tuning rate limits / OPSEC

Edit [`repkit/tool_defaults.conf`](repkit/tool_defaults.conf) — bash arrays, no code changes:

```bash
NUCLEI_DEFAULTS=(-rl 150 -c 25 -bs 25 -timeout 10 -stats -duc -severity critical,high)
HTTPX_DEFAULTS=(-rl 150 -threads 50 -timeout 10 -retries 1)
NAABU_DEFAULTS=(-rate 1000 -c 25 -warm-up-time 2)
FFUF_DEFAULTS=(-rate 50 -t 40)
KATANA_DEFAULTS=(-rl 150 -c 10 -d 3)
```

Operator-supplied flags on the command line override these.

**Nuclei follow-up passes** when the auto run flags critical/high only:
```bash
# Medium/low pass after auto:
nuclei -l ~/engagements/example.com/.aggregates/ext_phase5_urls.txt -severity medium,low

# Full unfiltered audit (slow — high-value targets only):
nuclei -l <input> -severity critical,high,medium,low,info
```

## Scope enforcement

`scope_guard` in [`repkit/lib/engagement.sh`](repkit/lib/engagement.sh) checks every wrapper invocation against `scope.txt` + `domains.txt`. Out-of-scope targets are rejected. Override once with:

```bash
OPSEC_ALLOW_OUT_OF_SCOPE=1 nmap <out-of-scope-host>
```

Override is logged to stderr.

## Bundle layout

`rpt collect -t ext` produces `<target>-ext-<YYYYMMDD>.tar.gz`:

```
example.com-ext-<date>/
├── manifest.json     (machine — reptr ingests)
├── summary.md        (human/LLM — per-tool extracted signal)
├── scope.txt
├── domains.txt
├── notes.md
├── recon/            (canvass)
├── uncover/
├── dnstwist/
├── cloud/            (cloud_enum)
├── dnsx/
├── naabu/
├── nmap/             (xml/gnmap/nmap)
├── httpx/            (json + plain URL list)
├── gowitness/        (sqlite + jsonl + screenshots/)
├── urlfinder/
├── katana/
├── ffuf/
└── nuclei/
```

Re-running `rpt collect` overwrites the same-day bundle.

## Bundle inspection

```bash
tar -tzf <bundle>.tar.gz                                        # list contents
tar -xzOf <bundle>.tar.gz <bundle-dir>/summary.md               # peek at one file
tar -xzf <bundle>.tar.gz                                        # extract
```

## Per-engagement file layout

```
~/engagements/example.com/
├── scope.txt
├── domains.txt
├── notes.md
├── .aggregates/          (chain-internal — not bundled)
│   ├── scope_clean.txt
│   ├── ext_subdomains.txt
│   ├── ext_dnsx_hosts.txt
│   └── ext_phase5_urls.txt
└── ext/
    └── <tool subdirs>/
```

## Adding a new collector

Drop [`collectors/external/<phase>/<toolname>.py`](collectors/external/recon/canvass.py):

```python
NAME = "toolname"
SUBDIR = "subdir"     # folder under ~/engagements/<client>/ext/

FILES = {
    "role_name":  "exact-file.json",
    "other":      "*_glob.txt",
}
```

No other code changes — bundling auto-detects.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENGAGEMENT_BASE` | `~/engagements` | Root directory for engagement data |
| `ENGAGEMENT_TYPE` | `ext` | Output subtree under the target; `rpt run` sets this automatically |
| `OPERATOR` | `$USER` | Operator name embedded in manifest |
| `OPSEC_ALLOW_OUT_OF_SCOPE` | `0` | Set to `1` to bypass scope_guard once |

## Dev

```bash
pip install -e ".[dev]"
python -m pytest tests/
```

## Uninstall

```bash
./uninstall.sh           # keeps ~/engagements
./uninstall.sh --all     # also wipes ~/engagements
```
