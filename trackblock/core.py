"""TRACKBLOCK core engine — stalkerware / spyware indicator detection.

The engine consumes a forensic evidence directory containing JSON artifacts
extracted from a device (no live device access is performed — this works on a
dump, exactly like MVT). It correlates the artifacts against a curated
indicator database and emits scored detections.

Evidence layout (any subset may be present):

    <evidence_dir>/
        manifest.json        -> {"platform": "ios"|"android", "device": "...",
                                  "extracted_at": "..."}
        apps.json            -> [{"package": "...", "name": "...",
                                  "install_source": "...", "version": "..."}]
        profiles.json        -> [{"identifier": "...", "name": "...",
                                  "removal_disallowed": true}]   (iOS MDM)
        accessibility.json   -> ["com.pkg.with.a11y.access", ...] (Android)
        device_admins.json   -> ["com.pkg.device.admin", ...]    (Android)
        processes.json       -> [{"name": "...", "path": "..."}]
        permissions.json     -> {"com.pkg": ["CAMERA","RECORD_AUDIO",...]}

All inputs are optional; missing files are simply skipped. Anything malformed
raises EvidenceError so the CLI can exit non-zero.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


class EvidenceError(Exception):
    """Raised when an evidence directory or artifact is missing/unreadable."""


# Severity weights drive the overall risk score.
SEVERITY_WEIGHT = {"info": 5, "low": 15, "medium": 30, "high": 60, "critical": 90}


@dataclass(frozen=True)
class Indicator:
    """A single stalkerware indicator-of-compromise."""

    ioc_id: str
    family: str
    platform: str  # "ios", "android", or "any"
    kind: str  # "package", "process", "profile", "behavior"
    pattern: str  # substring matched case-insensitively
    severity: str
    description: str


# Curated IOC set covering well-documented commercial stalkerware families.
# Patterns are matched as case-insensitive substrings against package ids /
# process paths / profile identifiers, mirroring MVT's stix-style matching.
INDICATORS: List[Indicator] = [
    Indicator("TB-0001", "FlexiSpy", "android", "package", "com.flexispy",
              "critical", "FlexiSpy commercial spyware package present."),
    Indicator("TB-0002", "FlexiSpy", "any", "process", "djflexispy",
              "critical", "FlexiSpy daemon process running."),
    Indicator("TB-0003", "mSpy", "android", "package", "com.bbm.mspy",
              "critical", "mSpy monitoring agent package present."),
    Indicator("TB-0004", "mSpy", "android", "package", "sys.framework",
              "high", "mSpy disguise package 'sys.framework'."),
    Indicator("TB-0005", "Cerberus", "android", "package", "com.lsdroid.cerberus",
              "high", "Cerberus anti-theft/monitoring app present."),
    Indicator("TB-0006", "Hoverwatch", "android", "package", "com.android.core.mahh",
              "critical", "Hoverwatch covert tracking package present."),
    Indicator("TB-0007", "TheTruthSpy", "android", "package", "com.systemservice",
              "high", "TheTruthSpy disguise package 'com.systemservice'."),
    Indicator("TB-0008", "Spyzie", "android", "package", "com.spyzie",
              "critical", "Spyzie monitoring package present."),
    Indicator("TB-0009", "KidsGuard", "android", "package", "com.clevguard",
              "high", "ClevGuard / KidsGuard Pro package present."),
    Indicator("TB-0010", "Spyera", "any", "package", "android.tether",
              "high", "Spyera covert package 'android.tether'."),
    Indicator("TB-0011", "Pegasus", "ios", "process", "bh.process",
              "critical", "NSO Pegasus 'bh' process artifact."),
    Indicator("TB-0012", "Pegasus", "ios", "process", "roleaboutd",
              "critical", "NSO Pegasus 'roleaboutd' process artifact."),
    Indicator("TB-0013", "Generic", "ios", "profile", "supervision",
              "medium", "Unexpected supervision/MDM profile installed."),
    Indicator("TB-0014", "iKeyMonitor", "any", "package", "com.ikeymonitor",
              "high", "iKeyMonitor keylogger package present."),
    Indicator("TB-0015", "Sideload", "android", "behavior", "sideloaded_surveillance",
              "medium", "Hidden app sideloaded outside an app store."),
]

# Permission combinations that strongly suggest covert surveillance when held
# by a hidden / sideloaded / non-store app.
SURVEILLANCE_PERMS = {"RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
                      "READ_SMS", "READ_CALL_LOG", "READ_CONTACTS"}

# Apps with no visible launcher entry are a classic stalkerware tell.
HIDDEN_FLAGS = ("hidden", "no_launcher", "disguised")


@dataclass
class Detection:
    """One matched indicator against the evidence."""

    ioc_id: str
    family: str
    severity: str
    kind: str
    artifact: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    """Full result of an audit run."""

    platform: str
    device: str
    artifacts_loaded: List[str] = field(default_factory=list)
    detections: List[Detection] = field(default_factory=list)
    risk_score: int = 0
    verdict: str = "clean"

    def finalize(self) -> "AuditReport":
        score = 0
        for d in self.detections:
            score += SEVERITY_WEIGHT.get(d.severity, 0)
        self.risk_score = min(score, 100)
        if any(d.severity == "critical" for d in self.detections):
            self.verdict = "compromised"
        elif self.risk_score >= 30:
            self.verdict = "suspicious"
        elif self.detections:
            self.verdict = "review"
        else:
            self.verdict = "clean"
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "trackblock",
            "platform": self.platform,
            "device": self.device,
            "artifacts_loaded": self.artifacts_loaded,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "detection_count": len(self.detections),
            "detections": [d.to_dict() for d in self.detections],
        }


def _read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"malformed JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc


def load_evidence(evidence_dir: str) -> Dict[str, Any]:
    """Load all known artifacts from an evidence directory into one dict."""
    if not os.path.isdir(evidence_dir):
        raise EvidenceError(f"evidence directory not found: {evidence_dir}")

    records: Dict[str, Any] = {"_loaded": []}
    known = ("manifest", "apps", "profiles", "accessibility",
             "device_admins", "processes", "permissions")
    for name in known:
        path = os.path.join(evidence_dir, f"{name}.json")
        if os.path.isfile(path):
            records[name] = _read_json(path)
            records["_loaded"].append(f"{name}.json")
    if len(records["_loaded"]) == 0:
        raise EvidenceError(f"no known artifacts found in {evidence_dir}")
    return records


def _match_indicators(platform: str, kind: str, artifact: str,
                      detail: str) -> List[Detection]:
    hits: List[Detection] = []
    # Guard against None / non-string values that survive upstream coercion.
    artifact = artifact if isinstance(artifact, str) else str(artifact or "")
    detail = detail if isinstance(detail, str) else str(detail or "")
    hay = artifact.lower()
    for ind in INDICATORS:
        if ind.kind != kind:
            continue
        if ind.platform not in ("any", platform):
            continue
        if ind.pattern.lower() in hay:
            hits.append(Detection(ind.ioc_id, ind.family, ind.severity,
                                   ind.kind, artifact, detail or ind.description))
    return hits


def _safe_list(value: Any, artifact_name: str) -> List[Any]:
    """Return *value* as a list, raising EvidenceError if it is non-iterable
    in an unexpected way (e.g. the JSON file contained an object instead of
    an array).  A falsy value (None / empty) becomes an empty list.
    """
    if not value:
        return []
    if not isinstance(value, list):
        raise EvidenceError(
            f"expected a JSON array for '{artifact_name}', "
            f"got {type(value).__name__}"
        )
    return value


def _safe_dict(value: Any, artifact_name: str) -> Dict[str, Any]:
    """Return *value* as a dict, raising EvidenceError if the wrong type."""
    if not value:
        return {}
    if not isinstance(value, dict):
        raise EvidenceError(
            f"expected a JSON object for '{artifact_name}', "
            f"got {type(value).__name__}"
        )
    return value


def _safe_flags(raw: Any) -> List[str]:
    """Coerce an app's 'flags' field to a list of lowercase strings.

    Tolerates None, missing keys, or non-list values (treats them as empty).
    """
    if not raw or not isinstance(raw, list):
        return []
    return [str(f).lower() for f in raw]


def audit_records(records: Dict[str, Any]) -> AuditReport:
    """Run the full detection pipeline over already-loaded evidence."""
    manifest = records.get("manifest") or {}
    if not isinstance(manifest, dict):
        manifest = {}
    platform = str(manifest.get("platform", "unknown")).lower()
    device = str(manifest.get("device", "unknown"))

    report = AuditReport(platform=platform, device=device,
                         artifacts_loaded=list(records.get("_loaded", [])))

    # 1) Installed application packages.
    apps = _safe_list(records.get("apps"), "apps")
    for app in apps:
        if not isinstance(app, dict):
            continue  # skip malformed entries silently
        pkg = str(app.get("package") or "")
        name = str(app.get("name") or pkg)
        report.detections.extend(
            _match_indicators(platform, "package", pkg, f"app '{name}'"))

        flags = _safe_flags(app.get("flags"))
        src = str(app.get("install_source") or "").lower()
        hidden = any(f in HIDDEN_FLAGS for f in flags)
        non_store = src not in ("", "app_store", "play_store", "system")
        if hidden and non_store:
            report.detections.extend(
                _match_indicators(platform, "behavior",
                                  "sideloaded_surveillance",
                                  f"hidden sideloaded app '{name}' ({pkg})"))

    # 2) Processes / daemons.
    for proc in _safe_list(records.get("processes"), "processes"):
        if not isinstance(proc, dict):
            continue
        pname = str(proc.get("name") or "")
        ppath = str(proc.get("path") or pname)
        report.detections.extend(
            _match_indicators(platform, "process", f"{pname} {ppath}",
                              f"process '{pname}'"))

    # 3) iOS configuration profiles.
    for prof in _safe_list(records.get("profiles"), "profiles"):
        if not isinstance(prof, dict):
            continue
        ident = str(prof.get("identifier") or "")
        pname = str(prof.get("name") or ident)
        text = f"{ident} {pname}"
        if prof.get("removal_disallowed"):
            text += " supervision"
        report.detections.extend(
            _match_indicators(platform, "profile", text,
                              f"profile '{pname}'"))

    # 4) Permission-correlation: non-store/hidden apps holding surveillance
    #    permission clusters are escalated even without a named IOC match.
    perms = _safe_dict(records.get("permissions"), "permissions")
    app_index = {str(a.get("package") or ""): a
                 for a in apps if isinstance(a, dict)}
    a11y = set(str(p) for p in
               _safe_list(records.get("accessibility"), "accessibility"))
    admins = set(str(p) for p in
                 _safe_list(records.get("device_admins"), "device_admins"))
    for pkg, granted in perms.items():
        granted_list = granted if isinstance(granted, list) else []
        gset = {str(g).upper() for g in granted_list}
        surv = gset & SURVEILLANCE_PERMS
        app = app_index.get(str(pkg), {})
        src = str(app.get("install_source") or "").lower()
        flags = _safe_flags(app.get("flags"))
        risky_install = src not in ("app_store", "play_store", "system", "")
        empowered = pkg in a11y or pkg in admins
        if len(surv) >= 3 and (risky_install or empowered
                               or any(f in HIDDEN_FLAGS for f in flags)):
            detail = (f"'{pkg}' holds {sorted(surv)}"
                      + (" + accessibility" if pkg in a11y else "")
                      + (" + device-admin" if pkg in admins else ""))
            report.detections.append(
                Detection("TB-PERM", "PermissionCluster", "high",
                          "behavior", pkg, detail))

    return report.finalize()


def audit_directory(evidence_dir: str) -> AuditReport:
    """Convenience: load an evidence directory and audit it."""
    return audit_records(load_evidence(evidence_dir))
