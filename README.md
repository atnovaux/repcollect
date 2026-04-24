# repcollect

Collects red team tool outputs from an engagement box and bundles them into a single transferable artifact for ingestion by reptr.

Two components in one repo:
- **rpt** — the CLI on the operator box (engagement management, phase orchestration, bundle creation)
- **repkit** (`repkit/`) — Kali setup: installs tools and wraps each one so output is forced into the engagement directory

## Install

```bash
git clone <repo>
cd repcollect
./install.sh
source ~/.zshrc
```

Requires Python 3.10+. Kali Linux. Runs as root.

## Workflow

**One engagement per target.** Every new target gets its own engagement — no stale data ever mixes between targets.

```bash
# start a new engagement
rpt new example.com
rpt use example.com

# run phases (wrappers auto-deposit under ~/engagements/example.com/ext/<tool>/)
rpt run -t ext -p recon
rpt run -t ext -p cloud
rpt run -t ext -p scanning
rpt run -t ext -p dns
rpt run -t ext -p web

# run tools manually when they need specific input (no auto-prompting)
trufflehog github --org=<target-org>
trufflehog filesystem /path/to/checkout
teamfiltration --enum --tenant-info --domain example.com

# bundle for handoff to reptr
rpt collect -t ext
# produces ./example.com-ext-<YYYYMMDD>.tar.gz
```

Switching between engagements:
```bash
rpt list                  # see all engagements (* marks active)
rpt use <other-target>    # switch active
rpt current               # print active
```

## Phases

| Phase | Tools (auto-run by `rpt run`) |
|---|---|
| `recon` | canvass |
| `cloud` | cloud-enum, roadtools, s3scanner |
| `scanning` | nmap, httpx, gowitness |
| `dns` | dig |
| `web` | ffuf |

**Not in any phase** (run manually — they need specific input):
- `trufflehog` — needs a source (git repo / filesystem / s3 bucket)
- `teamfiltration` — auth attacks; too dangerous to mass-run

## Directory layout

```
~/engagements/example.com/
└── ext/
    ├── recon/        (canvass output)
    ├── cloud/        (cloud-enum)
    ├── roadtools/
    ├── s3scanner/
    ├── nmap/
    ├── httpx/
    ├── gowitness/
    ├── trufflehog/
    ├── spray/        (teamfiltration)
    ├── dns/          (dig)
    └── ffuf/
```

Wrappers default to `ENGAGEMENT_TYPE=ext` — no env var needed.

## Bundle format

```
example.com-ext-20260424.tar.gz
└── example.com-ext-20260424/
    ├── manifest.json
    └── <tool-subdir>/
        └── <tool output files>
```

Re-running `rpt collect` overwrites the existing same-day bundle.

## Adding a new collector

Create `collectors/external/<phase>/<toolname>.py`:

```python
NAME = "toolname"
SUBDIR = "subdir"   # folder under ~/engagements/<target>/<type>/

FILES = {
    "role_name": "exact-file.json",
    "other_role": "*_glob.txt",
}
```

See [collectors/external/recon/canvass.py](collectors/external/recon/canvass.py) for a full example.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENGAGEMENT_BASE` | `~/engagements` | Root directory for all engagement data |
| `OPERATOR` | `$USER` | Operator name embedded in manifest |
| `ENGAGEMENT_TYPE` | `ext` | Output subtree under the target; `rpt run` sets this automatically |

## Dev

```bash
pip install -e ".[dev]"
python -m pytest tests/
```

## Uninstall

```bash
./uninstall.sh          # keeps ~/engagements
./uninstall.sh --all    # also wipes ~/engagements
```
