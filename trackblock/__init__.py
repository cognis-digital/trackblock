"""TRACKBLOCK — Family phone stalkerware audit (MVT-class forensics).

A zero-dependency, standard-library-only toolkit that audits a forensic
artifact dump from an iOS or Android device for indicators of stalkerware /
spyware / commercial surveillance apps.

Inspired by the spirit of mvt-project/mvt: it ingests an evidence directory
(installed app list, configuration profiles, accessibility/admin grants,
process list, etc.), correlates it against a built-in indicator-of-compromise
(IOC) database, and produces a structured threat report.

This is a defensive / consent-based tool intended to help victims of intimate
partner surveillance check their own (or a family member's, with consent)
device.
"""

from .core import (
    Detection,
    AuditReport,
    Indicator,
    INDICATORS,
    audit_directory,
    audit_records,
    load_evidence,
)

TOOL_NAME = "trackblock"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Detection",
    "AuditReport",
    "Indicator",
    "INDICATORS",
    "audit_directory",
    "audit_records",
    "load_evidence",
]
