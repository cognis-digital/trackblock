# Roadmap

Direction for `trackblock`. Everything here is additive — existing commands,
flags, output shapes and indicator IDs remain stable.

## Near-term (0.x)

- **Indicator database growth** — expand the curated IOC set with more
  documented commercial stalkerware families and iOS mercenary-spyware process
  artifacts; keep IDs append-only so SARIF/rule mappings stay valid.
- **External indicator packs** — load an additional IOC file
  (`--indicators path.json`) so teams can extend detection without forking.
- **Network artifacts** — optional `network.json` (DNS/host/connection) pass so
  known C2 / exfil endpoints become a detectable artifact kind.
- **Richer SARIF** — attach `help`/`helpUri` per rule and a run-level
  invocation record for cleaner code-scanning UX.
- **HTML report** — `--format html` single-file report for non-technical
  recipients (family / advocates).

## Mid-term

- **Acquisition helpers** — documented, consent-first collection scripts that
  produce the evidence-dump layout on macOS/Linux (no live-device exploitation).
- **Timeline view** — correlate `extracted_at` / install times into a temporal
  narrative of when surveillance was introduced.
- **Confidence scoring** — separate *likelihood* from *severity* so a single
  weak signal reads differently from corroborated multi-artifact detections.
- **Baseline diffing** — compare two dumps over time to surface newly appeared
  apps/profiles/permissions.
- **Localization** — translatable finding descriptions for survivor-facing use.

## Long-term

- **Pluggable detectors** — a small entry-point interface so third parties can
  register detectors (packages, processes, behaviors) as installable plugins.
- **Signed indicator feeds** — verifiable, versioned IOC distribution.
- **Cross-tool interop** — deepen the `cognis-connect` bridge (STIX/TAXII/MISP)
  so findings flow into shared threat-intel with provenance.
- **Guided remediation** — map each family to vetted, jurisdiction-aware safety
  and removal guidance (with a strong human-in-the-loop / safety-planning
  emphasis for intimate-partner-surveillance cases).

## Non-goals

- No live-device exploitation, rooting/jailbreaking, or covert collection.
- No offensive/spyware capability — `trackblock` is strictly a **detection and
  survivor-protection** tool.
- No telemetry or network calls in the core audit path; it stays offline by
  default.

Have an idea or a new indicator? Open an issue or a PR — see
[CONTRIBUTING.md](CONTRIBUTING.md).
