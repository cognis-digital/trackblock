"""TRACKBLOCK command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    SEVERITY_ORDER,
    VERDICT_ORDER,
    AuditReport,
    EvidenceError,
    audit_directory,
    indicators_as_dicts,
)


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


FORMATS = ("table", "json", "sarif", "csv")


def _add_audit_arguments(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("evidence_dir",
                    help="path to the extracted evidence directory")
    sp.add_argument("--min-severity", choices=SEVERITY_ORDER, default=None,
                    help="drop detections below this severity before "
                         "reporting and re-score (default: keep all)")
    sp.add_argument("--fail-on", choices=(*VERDICT_ORDER, "never"),
                    default="review",
                    help="lowest verdict that yields a non-zero exit code "
                         "(default: review — i.e. exit non-zero unless clean; "
                         "'never' always exits 0)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Family phone stalkerware audit (MVT-class forensics). "
                    "Scans an offline evidence dump for spyware indicators.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=FORMATS, default="table",
                        help="output format (default: table)")

    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit",
                           help="audit an evidence directory for stalkerware")
    _add_audit_arguments(audit)
    # `scan` is an alias of `audit` — same behaviour, friendlier verb.
    scan = sub.add_parser("scan",
                          help="alias of 'audit' — scan an evidence directory")
    _add_audit_arguments(scan)

    listing = sub.add_parser("list-indicators",
                             help="print the built-in indicator database")
    listing.add_argument("--platform", choices=("any", "ios", "android"),
                         default="any",
                         help="only show indicators for this platform")
    return parser


def _exit_code(verdict: str, fail_on: str) -> int:
    """Map a verdict onto an exit code given the --fail-on threshold."""
    if fail_on == "never":
        return 0
    rank = {v: i for i, v in enumerate(VERDICT_ORDER)}
    return 1 if rank.get(verdict, 0) >= rank[fail_on] else 0


def _print_indicators_table(rows: List[dict]) -> None:
    print(f"TRACKBLOCK indicators ({len(rows)})")
    print(f"  {'IOC':<9} {'SEVERITY':<9} {'PLATFORM':<8} {'KIND':<9} "
          f"{'FAMILY':<16} PATTERN")
    print(f"  {'-'*9} {'-'*9} {'-'*8} {'-'*9} {'-'*16} {'-'*24}")
    for r in rows:
        print(f"  {r['ioc_id']:<9} {r['severity']:<9} {r['platform']:<8} "
              f"{r['kind']:<9} {r['family']:<16} {r['pattern']}")


def _emit_report(report: AuditReport, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report.to_dict(), indent=2))
    elif fmt == "sarif":
        print(json.dumps(report.to_sarif(), indent=2))
    elif fmt == "csv":
        print(report.to_csv(), end="")
    else:
        _print_table(report)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "list-indicators":
        rows = indicators_as_dicts(args.platform)
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        elif args.format == "csv":
            import csv as _csv
            import io as _io
            buf = _io.StringIO()
            w = _csv.writer(buf, lineterminator="\n")
            w.writerow(["ioc_id", "family", "platform", "kind",
                        "pattern", "severity", "description"])
            for r in rows:
                w.writerow([r["ioc_id"], r["family"], r["platform"],
                            r["kind"], r["pattern"], r["severity"],
                            r["description"]])
            print(buf.getvalue(), end="")
        else:
            _print_indicators_table(rows)
        return 0

    if args.command in ("audit", "scan"):
        try:
            report = audit_directory(args.evidence_dir)
        except EvidenceError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.min_severity:
            report = report.filter_min_severity(args.min_severity)

        _emit_report(report, args.format)

        # Non-zero exit when the device is not clean, so the tool is usable
        # as a gate in scripts / cron audits. Threshold is tunable via
        # --fail-on; the default reproduces the historical clean==0 behaviour.
        return _exit_code(report.verdict, args.fail_on)

    parser.error("unknown command")
    return 2  # unreachable, keeps type-checkers happy


if __name__ == "__main__":
    raise SystemExit(main())
