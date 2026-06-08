"""Smoke tests for TRACKBLOCK (no network, stdlib only)."""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trackblock import TOOL_NAME, TOOL_VERSION, audit_records  # noqa: E402
from trackblock.cli import main  # noqa: E402
from trackblock.core import EvidenceError, audit_directory  # noqa: E402

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "01-basic", "evidence")


class TestCore(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "trackblock")
        self.assertTrue(TOOL_VERSION)

    def test_clean_device(self):
        records = {
            "_loaded": ["manifest.json", "apps.json"],
            "manifest": {"platform": "android", "device": "clean"},
            "apps": [{"package": "com.android.chrome", "name": "Chrome",
                      "install_source": "play_store"}],
        }
        report = audit_records(records)
        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.detections, [])
        self.assertEqual(report.risk_score, 0)

    def test_known_family_match(self):
        records = {
            "_loaded": ["apps.json"],
            "manifest": {"platform": "android", "device": "x"},
            "apps": [{"package": "com.flexispy.agent", "name": "x",
                      "install_source": "sideload"}],
        }
        report = audit_records(records)
        ids = {d.ioc_id for d in report.detections}
        self.assertIn("TB-0001", ids)
        self.assertEqual(report.verdict, "compromised")
        self.assertGreater(report.risk_score, 0)

    def test_permission_cluster(self):
        records = {
            "_loaded": ["apps.json", "permissions.json"],
            "manifest": {"platform": "android", "device": "x"},
            "apps": [{"package": "com.unknown.app", "name": "x",
                      "install_source": "sideload", "flags": ["hidden"]}],
            "permissions": {"com.unknown.app":
                            ["RECORD_AUDIO", "CAMERA", "READ_SMS"]},
        }
        report = audit_records(records)
        self.assertTrue(any(d.ioc_id == "TB-PERM" for d in report.detections))

    def test_demo_directory(self):
        report = audit_directory(DEMO)
        self.assertNotEqual(report.verdict, "clean")
        ids = {d.ioc_id for d in report.detections}
        self.assertIn("TB-0007", ids)
        self.assertIn("TB-PERM", ids)

    def test_missing_directory_raises(self):
        with self.assertRaises(EvidenceError):
            audit_directory(os.path.join(DEMO, "does-not-exist"))


class TestCLI(unittest.TestCase):
    def test_json_format_and_exit_code(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "audit", DEMO])
        self.assertEqual(rc, 1)  # not clean -> non-zero
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["tool"], "trackblock")
        self.assertGreater(payload["detection_count"], 0)
        self.assertIn(payload["verdict"],
                      ("review", "suspicious", "compromised"))

    def test_table_format(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["audit", DEMO])
        self.assertEqual(rc, 1)
        self.assertIn("TRACKBLOCK audit", buf.getvalue())

    def test_missing_dir_exit_2(self):
        rc = main(["audit", os.path.join(DEMO, "nope")])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
