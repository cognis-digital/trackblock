"""TRACKBLOCK command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import AuditReport, EvidenceError, audit_directory


VERDICT_LABEL = {
    "clean": "CLEAN",
    "review": "REVIEW",
    "suspicious": "SUSPICIOUS",
    "compromised": "COMPROMISED",
}


def _print_table(report: AuditReport) -> None:
    print(f"TRACKBLOCK audit -- {report.platform} / {report.device}")
    print(f"  artifacts: {', '.join(report.artifacts_loaded) or '(none)'}")
    print(f"  verdict  : {VERDICT_LABEL.get(report.verdict, report.verdict)}"
          f"  (risk score {report.risk_score}/100)")
    print(f"  findings : {len(report.detections)}")
    if not report.detections:
        print("  no stalkerware indicators matched.")
        return
    print()
    print(f"  {'IOC':<9} {'SEVERITY':<9} {'FAMILY':<16} DETAIL")
    print(f"  {'-'*9} {'-'*9} {'-'*16} {'-'*30}")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for d in sorted(report.detections,
                    key=lambda x: order.get(x.severity, 9)):
        print(f"  {d.ioc_id:<9} {d.severity:<9} {d.family:<16} {d.detail}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Family phone stalkerware audit (MVT-class forensics). "
                    "Scans an offline evidence dump for spyware indicators.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=("table", "json"), default="table",
                        help="output format (default: table)")

    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit",
                           help="audit an evidence directory for stalkerware")
    audit.add_argument("evidence_dir",
                       help="path to the extracted evidence directory")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        try:
            report = audit_directory(args.evidence_dir)
        except EvidenceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            _print_table(report)

        # Non-zero exit when the device is not clean, so the tool is usable
        # as a gate in scripts / cron audits.
        return 0 if report.verdict == "clean" else 1

    parser.error("unknown command")
    return 2  # unreachable, keeps type-checkers happy


if __name__ == "__main__":
    raise SystemExit(main())
