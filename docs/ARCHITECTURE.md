# Architecture

`trackblock` is a small, dependency-free forensic engine. It never touches a
live device — it consumes an **offline evidence dump** (a directory of JSON
artifacts extracted from a phone) and correlates it against a curated indicator
database. The analysis is therefore fully reproducible and safe to re-run.

## Pipeline

```
evidence dir ──▶ load_evidence ──▶ audit_records ──▶ finalize ──▶ render
                (parse JSON)        (correlate)       (score)     (table/json/sarif/csv)
```

1. **`load_evidence(dir)`** — reads any subset of the known artifacts
   (`manifest`, `apps`, `processes`, `profiles`, `accessibility`,
   `device_admins`, `permissions`). Missing files are skipped; a malformed file
   raises `EvidenceError`; an empty/unknown directory raises `EvidenceError`.
   The loaded artifact names are recorded under `_loaded`.

2. **`audit_records(records)`** — the correlation core. It runs four passes:
   - **Packages** — each installed app package is matched (case-insensitive
     substring) against `package`-kind indicators for the device platform.
   - **Processes** — process name + path matched against `process`-kind
     indicators (platform-scoped; iOS implant artifacts never fire on Android).
   - **iOS profiles** — configuration profiles matched against `profile`-kind
     indicators; a `removal_disallowed` profile adds a `supervision` signal.
   - **Permission correlation** — a `behavior` heuristic (`TB-PERM`): an app
     holding ≥3 surveillance permissions is escalated when it is
     sideloaded/hidden **or** empowered via accessibility / device-admin.

3. **`AuditReport.finalize()`** — sums severity weights into a `risk_score`
   (capped at 100) and derives a `verdict` on the ladder
   `clean → review → suspicious → compromised`. Any `critical` detection forces
   `compromised`.

4. **Rendering** — `to_dict` (json), `to_sarif` (SARIF 2.1.0), `to_csv`, or the
   CLI table. `filter_min_severity` produces a re-scored copy keeping only
   findings at/above a severity.

## Key types (`trackblock.core`)

| Type / function | Role |
|---|---|
| `Indicator` (frozen dataclass) | One IOC: id, family, platform, kind, pattern, severity, description. |
| `INDICATORS` | The curated IOC list (25+ entries). |
| `SURVEILLANCE_PERMS` | Permission set that drives the `TB-PERM` heuristic. |
| `Detection` | A single matched finding. |
| `AuditReport` | Full result: artifacts, detections, score, verdict + serializers. |
| `EvidenceError` | Raised for missing/unreadable/empty evidence. |
| `load_evidence` / `audit_records` / `audit_directory` | Load + run the pipeline. |
| `scan(dir) -> dict` | Stable programmatic entry point (used by the MCP server). |
| `iter_indicators` / `indicators_as_dicts` | Introspect the IOC database. |

## Scoring model

| Severity | Weight |
|---|---|
| info | 5 |
| low | 15 |
| medium | 30 |
| high | 60 |
| critical | 90 |

`risk_score = min(100, Σ weights)`. Verdict: `compromised` if any critical, else
`suspicious` if score ≥ 30, else `review` if any detection, else `clean`.

## Design principles

- **Zero runtime dependencies** — stdlib only; extras (`connect`, `mcp`, `web`)
  are optional and lazily imported.
- **Offline & reproducible** — same dump always yields the same verdict.
- **Additive IOC database** — new families extend `INDICATORS`; existing IDs are
  stable so downstream SARIF/rule mappings don't break.
