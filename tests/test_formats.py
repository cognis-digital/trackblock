"""Serialization tests: SARIF 2.1.0, CSV and severity filtering."""

from __future__ import annotations

import csv
import io
import os

from trackblock.core import audit_directory, audit_records

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "01-basic", "evidence")


def _dirty_report():
    return audit_records({
        "_loaded": ["apps.json"],
        "manifest": {"platform": "android", "device": "x"},
        "apps": [{"package": "com.flexispy.a", "name": "svc"},
                 {"package": "com.systemservice", "name": "sys",
                  "install_source": "sideload", "flags": ["hidden"]}],
    })


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #

def test_sarif_top_level_shape():
    sarif = audit_directory(DEMO).to_sarif()
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "trackblock"
    assert driver["informationUri"].startswith("https://")


def test_sarif_rules_are_deduped_and_results_complete():
    rep = _dirty_report()
    sarif = rep.to_sarif()
    run = sarif["runs"][0]
    # one result per detection
    assert len(run["results"]) == len(rep.detections)
    # rules deduped by ioc_id
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert set(rule_ids) == {d.ioc_id for d in rep.detections}


def test_sarif_levels_map_severity():
    rep = _dirty_report()
    run = rep.to_sarif()["runs"][0]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    # FlexiSpy is critical -> error
    assert levels["TB-0001"] == "error"
    for r in run["results"]:
        assert r["level"] in ("error", "warning", "note")


def test_sarif_run_properties_carry_verdict():
    rep = _dirty_report()
    props = rep.to_sarif()["runs"][0]["properties"]
    assert props["verdict"] == rep.verdict
    assert props["risk_score"] == rep.risk_score
    assert props["platform"] == "android"


def test_sarif_clean_device_has_no_results():
    rep = audit_records({
        "_loaded": ["apps.json"],
        "manifest": {"platform": "android", "device": "clean"},
        "apps": [{"package": "com.android.chrome", "name": "Chrome",
                  "install_source": "play_store"}]})
    run = rep.to_sarif()["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #

def test_csv_header_and_rows():
    rep = _dirty_report()
    text = rep.to_csv()
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["ioc_id", "severity", "family", "kind",
                       "artifact", "detail"]
    assert len(rows) == 1 + len(rep.detections)


def test_csv_rows_sorted_most_severe_first():
    rep = _dirty_report()
    rows = list(csv.reader(io.StringIO(rep.to_csv())))[1:]
    order = ["critical", "high", "medium", "low", "info"]
    idx = [order.index(r[1]) for r in rows]
    assert idx == sorted(idx)


def test_csv_clean_device_header_only():
    rep = audit_records({
        "_loaded": [], "manifest": {"platform": "android", "device": "x"},
        "apps": [{"package": "com.android.chrome", "name": "C",
                  "install_source": "play_store"}]})
    rows = list(csv.reader(io.StringIO(rep.to_csv())))
    assert len(rows) == 1  # header only


# --------------------------------------------------------------------------- #
# min-severity filtering
# --------------------------------------------------------------------------- #

def test_filter_min_severity_keeps_only_critical():
    rep = _dirty_report()
    filtered = rep.filter_min_severity("critical")
    assert all(d.severity == "critical" for d in filtered.detections)
    assert filtered.detections  # flexispy is critical


def test_filter_min_severity_rescoring_can_clean():
    # demo has only high/medium findings; filtering to critical -> clean.
    rep = audit_directory(DEMO)
    filtered = rep.filter_min_severity("critical")
    assert filtered.detections == []
    assert filtered.verdict == "clean"
    assert filtered.risk_score == 0


def test_filter_does_not_mutate_original():
    rep = _dirty_report()
    before = len(rep.detections)
    rep.filter_min_severity("critical")
    assert len(rep.detections) == before


def test_filter_unknown_severity_raises():
    rep = _dirty_report()
    import pytest
    with pytest.raises(ValueError):
        rep.filter_min_severity("bogus")
