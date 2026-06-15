#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import sys
import urllib.request

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True, help="Destination URL (https://…)")
    ap.add_argument("--header", action="append", default=[], help="Key: Value")
    ap.add_argument("--timeout", type=int, default=15,
                    help="HTTP timeout in seconds (default: 15)")
    args = ap.parse_args()

    # Validate URL scheme to avoid accidental file:// or ftp:// targets.
    if not args.url.startswith(("http://", "https://")):
        print("error: --url must begin with http:// or https://", file=sys.stderr)
        return 2

    # Validate timeout is a positive integer.
    if args.timeout < 1:
        print("error: --timeout must be a positive integer", file=sys.stderr)
        return 2

    payload = sys.stdin.read().encode("utf-8")
    if not payload.strip():
        print("error: no JSON payload received on stdin", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(f"error: malformed --header (expected 'Key: Value'): {h!r}",
                  file=sys.stderr)
            return 2
        k, _, v = h.partition(":")
        k = k.strip()
        if not k:
            print(f"error: empty header name in: {h!r}", file=sys.stderr)
            return 2
        req.add_header(k, v.strip())
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
