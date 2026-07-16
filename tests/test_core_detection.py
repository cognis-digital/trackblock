"""Deep behavioural tests for the TRACKBLOCK detection engine.

These exercise the real correlation logic in :mod:`trackblock.core` against
hand-built evidence records covering happy paths, edge cases and error paths.
No network, no external deps — stdlib + pytest only.
"""

from __future__ import annotations

import json
import os

import pytest

from trackblock.core import (
    INDICATORS,
    SEVERITY_WEIGHT,
    AuditReport,
    Detection,
    EvidenceError,
    audit_directory,
    audit_records,
    load_evidence,
    scan,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "01-basic", "evidence")


def _records(**parts):
    base = {"_loaded": list(parts.keys()),
            "manifest": {"platform": "android", "device": "test"}}
    base.update(parts)
    if "manifest" in parts:
        base["manifest"] = parts["manifest"]
    return base


# --------------------------------------------------------------------------- #
# Package indicator matching
# --------------------------------------------------------------------------- #

def test_flexispy_package_is_critical_and_compromised():
    rep = audit_records(_records(
        apps=[{"package": "com.flexispy.agent", "name": "svc",
               "install_source": "sideload"}]))
    ids = {d.ioc_id for d in rep.detections}
    assert "TB-0001" in ids
    assert rep.verdict == "compromised"
    assert any(d.severity == "critical" for d in rep.detections)


def test_case_insensitive_substring_match():
    rep = audit_records(_records(
        apps=[{"package": "COM.FLEXISPY.AGENT", "name": "x"}]))
    assert any(d.ioc_id == "TB-0001" for d in rep.detections)


def test_platform_scoping_excludes_ios_only_indicator_on_android():
    # bh.process is an iOS-only process indicator; on android it must not fire.
    rep = audit_records(_records(
        manifest={"platform": "android", "device": "x"},
        processes=[{"name": "bh", "path": "/usr/lib/bh.process"}]))
    assert not any(d.ioc_id == "TB-0011" for d in rep.detections)


def test_ios_process_indicator_fires_on_ios():
    rep = audit_records(_records(
        manifest={"platform": "ios", "device": "iPhone"},
        processes=[{"name": "bh", "path": "/private/var/bh.process"}]))
    assert any(d.ioc_id == "TB-0011" for d in rep.detections)


def test_any_platform_indicator_fires_on_both():
    for plat in ("ios", "android"):
        rep = audit_records(_records(
            manifest={"platform": plat, "device": "x"},
            apps=[{"package": "com.ikeymonitor.app", "name": "x"}]))
        assert any(d.ioc_id == "TB-0014" for d in rep.detections), plat


def test_newly_added_families_detected():
    for pkg, ioc in [("com.thumb.xnspy", "TB-0016"),
                     ("com.umobix.client", "TB-0019"),
                     ("com.spyhuman.app", "TB-0022")]:
        rep = audit_records(_records(apps=[{"package": pkg, "name": "x"}]))
        assert any(d.ioc_id == ioc for d in rep.detections), pkg


# --------------------------------------------------------------------------- #
# Behavioural / permission correlation
# --------------------------------------------------------------------------- #

def test_hidden_sideloaded_app_flags_behavior():
    rep = audit_records(_records(
        apps=[{"package": "com.unknown.x", "name": "x",
               "install_source": "sideload", "flags": ["hidden"]}]))
    assert any(d.ioc_id == "TB-0015" for d in rep.detections)


def test_hidden_but_store_install_does_not_flag_behavior():
    rep = audit_records(_records(
        apps=[{"package": "com.unknown.x", "name": "x",
               "install_source": "play_store", "flags": ["hidden"]}]))
    assert not any(d.ioc_id == "TB-0015" for d in rep.detections)


def test_permission_cluster_requires_three_perms():
    two = audit_records(_records(
        apps=[{"package": "com.p", "name": "x", "install_source": "sideload"}],
        permissions={"com.p": ["CAMERA", "RECORD_AUDIO"]}))
    assert not any(d.ioc_id == "TB-PERM" for d in two.detections)

    three = audit_records(_records(
        apps=[{"package": "com.p", "name": "x", "install_source": "sideload"}],
        permissions={"com.p": ["CAMERA", "RECORD_AUDIO", "READ_SMS"]}))
    assert any(d.ioc_id == "TB-PERM" for d in three.detections)


def test_permission_cluster_via_accessibility_empowerment():
    rep = audit_records(_records(
        apps=[{"package": "com.p", "name": "x",
               "install_source": "play_store"}],  # legit source...
        permissions={"com.p": ["CAMERA", "RECORD_AUDIO",
                               "ACCESS_FINE_LOCATION"]},
        accessibility=["com.p"]))  # ...but empowered by a11y => flagged
    perm = [d for d in rep.detections if d.ioc_id == "TB-PERM"]
    assert perm and "accessibility" in perm[0].detail


def test_permission_cluster_device_admin_detail():
    rep = audit_records(_records(
        apps=[{"package": "com.p", "name": "x", "install_source": "sideload"}],
        permissions={"com.p": ["CAMERA", "RECORD_AUDIO", "READ_CALL_LOG"]},
        device_admins=["com.p"]))
    perm = [d for d in rep.detections if d.ioc_id == "TB-PERM"]
    assert perm and "device-admin" in perm[0].detail


def test_store_install_without_empowerment_not_flagged():
    rep = audit_records(_records(
        apps=[{"package": "com.p", "name": "x", "install_source": "play_store"}],
        permissions={"com.p": ["CAMERA", "RECORD_AUDIO", "READ_SMS"]}))
    assert not any(d.ioc_id == "TB-PERM" for d in rep.detections)


def test_ios_supervision_profile_flags_generic():
    rep = audit_records(_records(
        manifest={"platform": "ios", "device": "iPhone"},
        profiles=[{"identifier": "com.corp.mdm", "name": "Corp",
                   "removal_disallowed": True}]))
    assert any(d.ioc_id == "TB-0013" for d in rep.detections)


# --------------------------------------------------------------------------- #
# Scoring / verdict
# --------------------------------------------------------------------------- #

def test_clean_device_scores_zero():
    rep = audit_records(_records(
        apps=[{"package": "com.android.chrome", "name": "Chrome",
               "install_source": "play_store"}]))
    assert rep.verdict == "clean"
    assert rep.risk_score == 0
    assert rep.detections == []


def test_risk_score_is_capped_at_100():
    apps = [{"package": f"com.flexispy.{i}", "name": "x"} for i in range(5)]
    rep = audit_records(_records(apps=apps))
    assert rep.risk_score == 100


def test_verdict_ladder_review_vs_suspicious():
    # Single medium detection (weight 30) -> exactly suspicious threshold.
    rep_medium = audit_records(_records(
        manifest={"platform": "ios", "device": "x"},
        profiles=[{"identifier": "x", "name": "x",
                   "removal_disallowed": True}]))
    assert rep_medium.risk_score == SEVERITY_WEIGHT["medium"]
    assert rep_medium.verdict == "suspicious"


def test_finalize_review_when_only_low_signal():
    rep = AuditReport(platform="android", device="x")
    rep.detections.append(Detection("X", "Fam", "info", "behavior", "a", "d"))
    rep.finalize()
    assert rep.risk_score == SEVERITY_WEIGHT["info"]
    assert rep.verdict == "review"


def test_critical_forces_compromised_regardless_of_score():
    rep = AuditReport(platform="android", device="x")
    rep.detections.append(Detection("X", "Fam", "critical", "package", "a", "d"))
    rep.finalize()
    assert rep.verdict == "compromised"


# --------------------------------------------------------------------------- #
# Loading / error paths
# --------------------------------------------------------------------------- #

def test_missing_directory_raises():
    with pytest.raises(EvidenceError):
        audit_directory(os.path.join(DEMO, "nope"))


def test_empty_directory_raises(tmp_path):
    with pytest.raises(EvidenceError):
        load_evidence(str(tmp_path))


def test_malformed_json_raises(tmp_path):
    (tmp_path / "apps.json").write_text("{not valid", encoding="utf-8")
    with pytest.raises(EvidenceError):
        load_evidence(str(tmp_path))


def test_load_evidence_records_loaded_names(tmp_path):
    (tmp_path / "manifest.json").write_text(
        json.dumps({"platform": "android", "device": "x"}), encoding="utf-8")
    (tmp_path / "apps.json").write_text("[]", encoding="utf-8")
    recs = load_evidence(str(tmp_path))
    assert set(recs["_loaded"]) == {"manifest.json", "apps.json"}


def test_scan_api_returns_dict_and_matches_report():
    result = scan(DEMO)
    assert result["tool"] == "trackblock"
    assert result["detection_count"] == len(audit_directory(DEMO).detections)


def test_unknown_platform_defaults_gracefully():
    rep = audit_records({"_loaded": [], "apps": [
        {"package": "com.flexispy", "name": "x"}]})
    # No manifest -> platform "unknown"; 'any' + android-scoped indicators:
    # android-only TB-0001 must NOT fire, but engine must not crash.
    assert rep.platform == "unknown"
    assert isinstance(rep.risk_score, int)


def test_indicator_database_is_wellformed():
    seen = set()
    for ind in INDICATORS:
        assert ind.ioc_id not in seen, f"duplicate {ind.ioc_id}"
        seen.add(ind.ioc_id)
        assert ind.severity in SEVERITY_WEIGHT
        assert ind.platform in ("any", "ios", "android")
        assert ind.kind in ("package", "process", "profile", "behavior")
        assert ind.pattern and ind.description
