# Usage

`trackblock` audits an **offline evidence dump** — a directory of JSON artifacts
extracted from a phone. It does not access a live device.

## Commands

```
trackblock audit <evidence_dir> [--min-severity S] [--fail-on V]
trackblock scan  <evidence_dir> [--min-severity S] [--fail-on V]   # alias of audit
trackblock list-indicators [--platform any|ios|android]
trackblock --version
```

Global: `--format {table,json,sarif,csv}` (before the subcommand).

## Evidence layout

Point the tool at a directory containing any subset of these files:

| File | Shape |
|---|---|
| `manifest.json` | `{"platform": "ios"\|"android", "device": "...", "extracted_at": "..."}` |
| `apps.json` | `[{"package": "...", "name": "...", "install_source": "...", "version": "...", "flags": ["hidden", ...]}]` |
| `processes.json` | `[{"name": "...", "path": "..."}]` |
| `profiles.json` (iOS) | `[{"identifier": "...", "name": "...", "removal_disallowed": true}]` |
| `accessibility.json` | `["com.pkg.with.a11y", ...]` |
| `device_admins.json` | `["com.pkg.device.admin", ...]` |
| `permissions.json` | `{"com.pkg": ["CAMERA","RECORD_AUDIO", ...]}` |

Missing files are skipped. A malformed file, or a directory with **no** known
artifacts, is an error (exit `2`).

## Examples

Audit the bundled demo and read the verdict:

```bash
trackblock audit demos/01-basic/evidence
trackblock audit demos/01-basic/evidence --format json | jq '.verdict, .risk_score'
```

Emit SARIF for GitHub code-scanning:

```bash
trackblock audit ./evidence --format sarif > trackblock.sarif
```

CSV for a spreadsheet / ticketing import:

```bash
trackblock scan ./evidence --format csv > findings.csv
```

Only fail a pipeline on a **confirmed** compromise, ignore lower-confidence
signals:

```bash
trackblock audit ./evidence --fail-on compromised
```

Reduce noise to high-confidence findings and re-score:

```bash
trackblock audit ./evidence --min-severity high --format json
```

Inspect the indicator database:

```bash
trackblock list-indicators --platform ios
trackblock list-indicators --format json | jq '.[].family' | sort -u
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Verdict is below the `--fail-on` threshold (default: only `clean` passes). |
| `1` | Verdict is at/above the threshold — findings present. |
| `2` | Evidence directory missing, empty, or an artifact was malformed. |

## Programmatic use

```python
from trackblock.core import scan, audit_directory

result = scan("demos/01-basic/evidence")   # -> dict (tool, verdict, detections, ...)
report = audit_directory("demos/01-basic/evidence")
print(report.verdict, report.risk_score)
print(report.to_sarif())                   # SARIF 2.1.0 dict
```
