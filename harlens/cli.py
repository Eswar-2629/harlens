"""Command-line interface for HARLens: audit and sanitize subcommands."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .checks import RANK, run_checks
from .har import HarError, load_json, parse_har
from .redact import sanitize_har
from .report import render_html, render_text, to_json_dict


def _write(path: Optional[str], text: str) -> None:
    if path is None:
        sys.stdout.write(text)
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        raise HarError(f"Cannot write '{path}': {exc.strerror or exc}.")


def _audit(args) -> int:
    data = load_json(args.file)
    entries, skipped = parse_har(data)
    findings = run_checks(entries)
    name = os.path.basename(args.file)
    if args.format == "json":
        out = json.dumps(to_json_dict(name, len(entries), skipped, findings), indent=2) + "\n"
    elif args.format == "html":
        out = render_html(name, len(entries), skipped, findings)
    else:
        out = render_text(name, len(entries), skipped, findings)
    _write(args.output, out)
    if args.fail_on != "none" and any(RANK[f.severity] >= RANK[args.fail_on] for f in findings):
        return 1
    return 0


def _sanitize(args) -> int:
    if os.path.abspath(args.file) == os.path.abspath(args.output):
        raise HarError("Output path must differ from the input path; the original is never overwritten.")
    data = load_json(args.file)
    parse_har(data)  # validates structure
    clean, count = sanitize_har(data)
    _write(args.output, json.dumps(clean, indent=2) + "\n")
    print(f"Wrote {args.output} with {count} redactions. Response bodies other than JSON and "
          "form data are not scanned; review the file before sharing it.", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="harlens", description="Offline security audit and sanitizer for HAR files.")
    p.add_argument("--version", action="version", version=f"harlens {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audit", help="check a HAR file for security problems")
    a.add_argument("file")
    a.add_argument("--format", choices=("text", "json", "html"), default="text")
    a.add_argument("-o", "--output", help="write the report here instead of stdout")
    a.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="none",
                   help="exit with code 1 if a finding at or above this severity exists")
    a.set_defaults(func=_audit)
    s = sub.add_parser("sanitize", help="write a copy of a HAR file with secrets redacted")
    s.add_argument("file")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(func=_sanitize)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except HarError as exc:
        print(f"harlens: error: {exc}", file=sys.stderr)
        return 2
