# repcollect

Collects red team tool outputs from an engagement box and bundles them into a single transferable artifact for ingestion by reptr.

## Install

```bash
git clone <repo>
cd repcollect
./install.sh
source ~/.bashrc
```

Requires Python 3.10+. No other dependencies.

## Usage

```bash
# set active engagement (via repkit)
eng use example.com

# run tools for a phase
rpt run -t ext -p recon
rpt run -t ext -p cloud
rpt run -t ext -p scanning

# bundle everything into an archive
rpt collect -t ext

# explicit target override
rpt collect -t ext -T example.com

# zip instead of tar.gz
rpt collect -t ext --format zip
```

## Phases

| Phase | Tools |
|---|---|
| `recon` | canvass, trufflehog |
| `cloud` | cloud-enum, roadtools, s3scanner |
| `scanning` | nmap, httpx, gowitness |
| `spray` | teamfiltration |
| `dns` | dig |
| `web` | ffuf |

## Directory convention

Output is organized by engagement type under `~/engagements/<target>/`:

```
~/engagements/example.com/
└── ext/
    ├── recon/
    ├── cloud/
    ├── scanning/
    └── ...
```

## Bundle format

Output: `./<target>-<type>-<YYYYMMDD>.tar.gz` in the current directory.

```
example.com-ext-20260423.tar.gz
└── example.com-ext-20260423/
    ├── manifest.json
    └── recon/
        ├── aad-raw.json
        └── ...
```

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

## Relationships

- **repkit** (`repkit/`) — installs tools and wrapper scripts, provides `eng` command
- **reptr** — ingests bundles produced by repcollect

## Dev

```bash
pip install -e ".[dev]"
python -m pytest tests/
```
