"""Hardening tests — edge cases, bad input, and error paths."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trackblock.cli import main  # noqa: E402
from trackblock.core import (  # noqa: E402
    EvidenceError,
    audit_records,
    load_evidence,
)


# ---------------------------------------------------------------------------
# core.py — type-safety / bad-input edge cases
# ---------------------------------------------------------------------------


class TestAuditRecordsBadTypes(unittest.TestCase):
    """audit_records must not crash when artifact lists contain wrong types."""

    def _base_records(self, **overrides):
        base = {
            "_loaded": ["manifest.json"],
            "manifest": {"platform": "android", "device": "test"},
        }
        base.update(overrides)
        return base

    def test_apps_list_with_non_dict_entry(self):
        """A string element inside the apps list must be skipped, not crash."""
        records = self._base_records(
            apps=["not-a-dict", {"package": "com.android.chrome",
                                  "name": "Chrome", "install_source": "play_store"}]
        )
        report = audit_records(records)
        self.assertEqual(report.verdict, "clean")

    def test_apps_none_flags_field(self):
        """An app entry where 'flags' is null/None must be treated as empty."""
        records = self._base_records(
            apps=[{"package": "com.example.app", "name": "App",
                   "install_source": "sideload", "flags": None}]
        )
        # Should not raise, and the sideloaded-without-hidden-flag should not
        # trigger the behavior IOC (hidden is False when flags is empty).
        report = audit_records(records)
        self.assertIsNotNone(report)

    def test_apps_string_flags_field(self):
        """An app entry where 'flags' is a string (not a list) is treated as empty."""
        records = self._base_records(
            apps=[{"package": "com.example.app", "name": "App",
                   "install_source": "sideload", "flags": "hidden"}]
        )
        report = audit_records(records)
        # 'hidden' as a bare string should NOT trigger sideload behavior IOC
        # because _safe_flags returns [] for non-list values.
        ioc_ids = {d.ioc_id for d in report.detections}
        self.assertNotIn("TB-0015", ioc_ids)

    def test_permissions_value_is_null(self):
        """A package entry in permissions.json with a null value is safe."""
        records = self._base_records(
            apps=[{"package": "com.spy", "name": "Spy",
                   "install_source": "sideload", "flags": ["hidden"]}],
            permissions={"com.spy": None},
        )
        # Should not crash; null granted list → empty set → no cluster
        report = audit_records(records)
        self.assertNotIn("TB-PERM", {d.ioc_id for d in report.detections})

    def test_permissions_value_is_non_list(self):
        """A package entry in permissions.json with an int value is safe."""
        records = self._base_records(
            apps=[{"package": "com.spy", "name": "Spy",
                   "install_source": "sideload", "flags": ["hidden"]}],
            permissions={"com.spy": 42},
        )
        report = audit_records(records)
        # Non-list granted → treated as empty → no TB-PERM
        self.assertNotIn("TB-PERM", {d.ioc_id for d in report.detections})

    def test_apps_wrong_type_raises(self):
        """If 'apps' is a JSON object instead of an array, raise EvidenceError."""
        records = self._base_records(apps={"package": "com.foo"})
        with self.assertRaises(EvidenceError):
            audit_records(records)

    def test_permissions_wrong_type_raises(self):
        """If 'permissions' is a list instead of an object, raise EvidenceError."""
        records = self._base_records(permissions=["CAMERA"])
        with self.assertRaises(EvidenceError):
            audit_records(records)

    def test_empty_apps_list(self):
        """An evidence package with no apps is valid and produces a clean report."""
        records = self._base_records(apps=[])
        report = audit_records(records)
        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.detections, [])


# ---------------------------------------------------------------------------
# core.py — load_evidence edge cases
# ---------------------------------------------------------------------------


class TestLoadEvidence(unittest.TestCase):
    def test_missing_directory_raises_evidence_error(self):
        with self.assertRaises(EvidenceError) as ctx:
            load_evidence("/nonexistent/path/to/evidence")
        self.assertIn("not found", str(ctx.exception))

    def test_directory_with_malformed_json_raises(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "apps.json")
            with open(bad, "w") as f:
                f.write("{not valid json")
            with self.assertRaises(EvidenceError) as ctx:
                load_evidence(d)
            self.assertIn("malformed JSON", str(ctx.exception))

    def test_empty_directory_raises_evidence_error(self):
        """A directory with no recognised artifact files raises EvidenceError."""
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(EvidenceError) as ctx:
                load_evidence(d)
            self.assertIn("no known artifacts", str(ctx.exception))


# ---------------------------------------------------------------------------
# cli.py — error exit paths
# ---------------------------------------------------------------------------


class TestCLIEdgeCases(unittest.TestCase):
    def test_missing_dir_returns_exit_2(self):
        rc = main(["audit", "/does/not/exist"])
        self.assertEqual(rc, 2)

    def test_malformed_json_returns_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "apps.json"), "w") as f:
                f.write("{bad json}")
            rc = main(["audit", d])
        self.assertEqual(rc, 2)

    def test_error_message_goes_to_stderr(self):
        err = io.StringIO()
        with redirect_stderr(err):
            main(["audit", "/no/such/dir"])
        self.assertIn("error", err.getvalue().lower())

    def test_clean_evidence_returns_exit_0(self):
        """A directory with only clean apps produces exit code 0."""
        with tempfile.TemporaryDirectory() as d:
            manifest = {"platform": "android", "device": "test-clean"}
            apps = [{"package": "com.android.chrome", "name": "Chrome",
                     "install_source": "play_store"}]
            with open(os.path.join(d, "manifest.json"), "w") as f:
                json.dump(manifest, f)
            with open(os.path.join(d, "apps.json"), "w") as f:
                json.dump(apps, f)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", d])
        self.assertEqual(rc, 0)
        self.assertIn("CLEAN", buf.getvalue())

    def test_json_format_with_bad_dir_returns_exit_2(self):
        """--format json still returns exit 2 on bad input."""
        rc = main(["--format", "json", "audit", "/no/such"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
