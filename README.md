# repcollect

Collects scattered red team tool outputs from an engagement box and bundles them into a single transferable artifact for ingestion by reptr.

## Install

```bash
git clone <repo>
cd repcollect
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires Python 3.10+. No external dependencies.

Add `source ~/repcollect/.venv/bin/activate` to your `.bashrc` to have `rpt` available in every session.

## Usage

```bash
# Uses $ENGAGEMENT env var
rpt

# Explicit target
rpt --target example.com

# Zip instead of tar.gz
rpt --target example.com --format zip
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENGAGEMENT` | — | Active engagement target domain |
| `ENGAGEMENT_BASE` | `~/engagements` | Root directory for all engagement data |
| `OPERATOR` | `$USER` | Operator name embedded in manifest |

## Directory convention

repcollect expects this layout under `$ENGAGEMENT_BASE/<target>/`:

```
~/engagements/example.com/
├── recon/        # canvass output
├── spray/        # TeamFiltration (future)
├── cloud/        # cloud_enum (future)
└── ...
```

If the target directory doesn't exist, `rpt` will error. Subdirectories for tools you didn't run are fine — they'll show up as `not found` in output and `missing_tools` in the manifest.

## Adding a new tool detector

Create `collectors/<toolname>.py` with three attributes:

```python
NAME = "toolname"        # identifier used in the manifest
SUBDIR = "subdir"        # subdirectory under $ENGAGEMENT_BASE/<target>/

FILES = {
    "role_name": "exact-file.json",   # exact filename
    "other_role": "*_glob.txt",        # glob pattern
}

# optional — return version string or None
def detect_version(subdir_path: Path) -> str | None:
    return None
```

No registration needed. `rpt` auto-discovers all modules in `collectors/`.

See [collectors/canvass.py](collectors/canvass.py) for a full example.

## Bundle format

Output: `./<target>-<YYYYMMDD>.tar.gz` (or `.zip`) in the current directory.

Archive layout:
```
example.com-20260423.tar.gz
└── example.com-20260423/
    ├── manifest.json
    └── recon/
        ├── aad-raw.json
        └── ...
```

`manifest.json` contains engagement metadata, per-tool file inventory, missing tools, and any skipped files (>500 MB).

## Relationships

- **repkit** — sets up the `$ENGAGEMENT_BASE/<target>/` directory convention that repcollect reads
- **reptr** — ingests bundles produced by repcollect; reads `manifest.json` to route files to the right parsers

## Dev

```bash
pip install -e ".[dev]"
python -m pytest tests/
```
