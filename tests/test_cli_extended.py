"""CLI-level tests for the new subcommands, formats and exit gates."""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout

from trackblock.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "01-basic", "evidence")


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


# --------------------------------------------------------------------------- #
# scan alias == audit
# --------------------------------------------------------------------------- #

def test_scan_alias_matches_audit_json():
    rc_a, out_a = _run(["--format", "json", "audit", DEMO])
    rc_s, out_s = _run(["--format", "json", "scan", DEMO])
    assert rc_a == rc_s == 1
    assert json.loads(out_a) == json.loads(out_s)


# --------------------------------------------------------------------------- #
# formats
# --------------------------------------------------------------------------- #

def test_sarif_format_output_parses():
    rc, out = _run(["--format", "sarif", "audit", DEMO])
    assert rc == 1
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_csv_format_has_header():
    rc, out = _run(["--format", "csv", "audit", DEMO])
    assert rc == 1
    assert out.splitlines()[0] == "ioc_id,severity,family,kind,artifact,detail"


# --------------------------------------------------------------------------- #
# --fail-on gate
# --------------------------------------------------------------------------- #

def test_fail_on_never_exits_zero_even_when_dirty():
    rc, _ = _run(["audit", DEMO, "--fail-on", "never"])
    assert rc == 0


def test_fail_on_compromised_suppresses_suspicious():
    # demo verdict is 'suspicious' -> below 'compromised' threshold -> exit 0
    rc, _ = _run(["audit", DEMO, "--fail-on", "compromised"])
    assert rc == 0


def test_default_fail_on_reproduces_legacy_behavior():
    rc, _ = _run(["audit", DEMO])
    assert rc == 1  # not clean -> non-zero, unchanged from before


def test_fail_on_review_clean_dir_exits_zero(tmp_path):
    (tmp_path / "manifest.json").write_text(
        json.dumps({"platform": "android", "device": "x"}), encoding="utf-8")
    (tmp_path / "apps.json").write_text(
        json.dumps([{"package": "com.android.chrome", "name": "Chrome",
                     "install_source": "play_store"}]), encoding="utf-8")
    rc, out = _run(["--format", "json", "audit", str(tmp_path)])
    assert rc == 0
    assert json.loads(out)["verdict"] == "clean"


# --------------------------------------------------------------------------- #
# --min-severity
# --------------------------------------------------------------------------- #

def test_min_severity_filters_and_can_flip_exit_code():
    # demo has no critical findings; filtering to critical => clean => exit 0
    rc, out = _run(["--format", "json", "audit", DEMO,
                    "--min-severity", "critical"])
    assert rc == 0
    assert json.loads(out)["detection_count"] == 0


# --------------------------------------------------------------------------- #
# list-indicators
# --------------------------------------------------------------------------- #

def test_list_indicators_json_count():
    rc, out = _run(["--format", "json", "list-indicators"])
    assert rc == 0
    rows = json.loads(out)
    assert len(rows) >= 15
    assert {"ioc_id", "family", "platform", "kind",
            "pattern", "severity", "description"} <= set(rows[0])


def test_list_indicators_platform_filter():
    rc, out = _run(["--format", "json", "list-indicators", "--platform", "ios"])
    assert rc == 0
    rows = json.loads(out)
    assert rows and all(r["platform"] in ("ios", "any") for r in rows)


def test_list_indicators_csv_header():
    rc, out = _run(["--format", "csv", "list-indicators"])
    assert rc == 0
    assert out.splitlines()[0].startswith("ioc_id,family,platform")


def test_list_indicators_table_default():
    rc, out = _run(["list-indicators"])
    assert rc == 0
    assert "TRACKBLOCK indicators" in out
    assert "TB-0001" in out


# --------------------------------------------------------------------------- #
# error paths preserved
# --------------------------------------------------------------------------- #

def test_missing_dir_still_exits_2():
    rc, _ = _run(["audit", os.path.join(DEMO, "nope")])
    assert rc == 2


def test_scan_missing_dir_exits_2():
    rc, _ = _run(["scan", os.path.join(DEMO, "nope")])
    assert rc == 2
