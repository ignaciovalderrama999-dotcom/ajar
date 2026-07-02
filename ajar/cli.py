"""Command-line entry point for ajar."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .models import Severity
from .report import render_json, render_sarif, render_terminal
from .rules import RuleError, load_rules
from .scanner import scan_path

_SEVERITY_CHOICES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ajar",
        description="Find the door you left open by default — fail-open logic "
        "and insecure config defaults. ajar analyzes and protects; it never attacks.",
        epilog="Use only on code you own or are authorized to review. ajar is a "
        "defensive aid, not a security guarantee. Provided AS IS with no warranty "
        "(Apache 2.0). See DISCLAIMER.md and ACCEPTABLE_USE.md.",
    )
    parser.add_argument("--version", action="version", version=f"ajar {__version__}")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", nargs="?", default=".", help="path to scan (default: current dir)")
    scan.add_argument(
        "--format",
        choices=["terminal", "json", "sarif"],
        default="terminal",
        help="output format (default: terminal)",
    )
    scan.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        default="medium",
        help="exit non-zero if a finding at or above this severity exists (default: medium)",
    )
    scan.add_argument(
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default="info",
        help="hide findings below this severity (default: info)",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="skip paths matching this glob (repeatable), e.g. --exclude tests --exclude '*.yml'",
    )
    scan.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="use a custom rules directory instead of the bundled one",
    )

    sub.add_parser("rules", help="list the loaded detection rules")

    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"ajar: path not found: {root}", file=sys.stderr)
        return 2

    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"ajar: {exc}", file=sys.stderr)
        return 2

    findings = scan_path(root, rules, tuple(args.exclude))

    min_sev = Severity(args.min_severity)
    findings = [f for f in findings if f.rule.severity >= min_sev]

    if args.format == "json":
        print(render_json(findings, str(root)))
    elif args.format == "sarif":
        print(render_sarif(findings, str(root)))
    else:
        print(render_terminal(findings, str(root)))

    fail_on = Severity(args.fail_on)
    if any(f.rule.severity >= fail_on for f in findings):
        return 1
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules()
    except RuleError as exc:
        print(f"ajar: {exc}", file=sys.stderr)
        return 2

    by_category: dict[str, list] = {}
    for rule in rules:
        by_category.setdefault(rule.category, []).append(rule)

    print(f"ajar has {len(rules)} rules across {len(by_category)} categories:\n")
    for category in sorted(by_category):
        print(f"# {category}")
        for rule in sorted(by_category[category], key=lambda r: r.id):
            print(f"  {rule.severity.value.upper():<8} {rule.id:<28} {rule.name}")
        print()
    return 0


def _force_utf8() -> None:
    # Windows consoles default to a legacy code page that mangles em dashes and
    # other UTF-8 output. Make output portable without touching rule content.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
