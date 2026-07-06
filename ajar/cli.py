"""Command-line entry point for ajar."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, find_config, load_config
from .models import Finding, Severity
from .report import (
    render_json,
    render_markdown_rules,
    render_report,
    render_sarif,
    render_terminal,
)
from .rules import RuleError, load_rules
from .scanner import scan_path

_SEVERITY_CHOICES = [s.value for s in Severity]
_DEFAULT_BASELINE = ".ajar-baseline.json"


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
        choices=["terminal", "json", "sarif", "report"],
        default="terminal",
        help="output format: terminal, json, sarif, or report (a graded Markdown audit)",
    )
    # Severity flags default to None so a .ajar.yml value can fill them in;
    # an explicit flag always wins.
    scan.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        default=None,
        help="exit non-zero if a finding at or above this severity exists (default: medium)",
    )
    scan.add_argument(
        "--min-severity",
        choices=_SEVERITY_CHOICES,
        default=None,
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
    scan.add_argument(
        "--config",
        type=Path,
        default=None,
        help="path to a .ajar.yml config file (default: auto-discovered)",
    )
    scan.add_argument(
        "--no-config",
        action="store_true",
        help="ignore any .ajar.yml config file",
    )
    scan.add_argument(
        "--baseline",
        type=Path,
        nargs="?",
        const=Path(_DEFAULT_BASELINE),
        default=None,
        metavar="FILE",
        help=f"ignore findings recorded in this baseline file (default file: {_DEFAULT_BASELINE})",
    )
    scan.add_argument(
        "--write-baseline",
        action="store_true",
        help="write current findings to the baseline file and exit 0",
    )

    rules = sub.add_parser("rules", help="list the loaded detection rules")
    rules.add_argument(
        "--format",
        choices=["terminal", "md"],
        default="terminal",
        help="output format (default: terminal)",
    )

    return parser


def _resolve(cli_value, config_value, default):
    if cli_value is not None:
        return cli_value
    if config_value is not None:
        return config_value
    return default


def _load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuleError(f"could not read baseline {path}: {exc}") from exc
    return set(data.get("fingerprints", []))


def _write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = {
        "tool": "ajar",
        "version": __version__,
        "fingerprints": sorted({f.fingerprint() for f in findings}),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"ajar: path not found: {root}", file=sys.stderr)
        return 2

    # Configuration: explicit --config, else auto-discover, unless --no-config.
    config = Config()
    if not args.no_config:
        config_path = args.config or find_config(root)
        if config_path is not None:
            if not config_path.is_file():
                print(f"ajar: config not found: {config_path}", file=sys.stderr)
                return 2
            try:
                config = load_config(config_path)
            except ConfigError as exc:
                print(f"ajar: {exc}", file=sys.stderr)
                return 2

    min_severity = _resolve(args.min_severity, config.min_severity, "info")
    fail_on = _resolve(args.fail_on, config.fail_on, "medium")
    excludes = tuple(args.exclude) + config.exclude

    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        print(f"ajar: {exc}", file=sys.stderr)
        return 2
    if config.disable:
        rules = [r for r in rules if r.id not in config.disable]

    findings = scan_path(root, rules, excludes)

    min_sev = Severity(min_severity)
    findings = [f for f in findings if f.rule.severity >= min_sev]

    if args.write_baseline:
        target = args.baseline or Path(_DEFAULT_BASELINE)
        _write_baseline(target, findings)
        print(f"ajar: wrote baseline with {len(findings)} findings to {target}")
        return 0

    if args.baseline is not None:
        try:
            known = _load_baseline(args.baseline)
        except RuleError as exc:
            print(f"ajar: {exc}", file=sys.stderr)
            return 2
        findings = [f for f in findings if f.fingerprint() not in known]

    if args.format == "json":
        print(render_json(findings, str(root)))
    elif args.format == "sarif":
        print(render_sarif(findings, str(root)))
    elif args.format == "report":
        print(render_report(findings, str(root)))
    else:
        print(render_terminal(findings, str(root)))

    fail_sev = Severity(fail_on)
    if any(f.rule.severity >= fail_sev for f in findings):
        return 1
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules()
    except RuleError as exc:
        print(f"ajar: {exc}", file=sys.stderr)
        return 2

    if args.format == "md":
        print(render_markdown_rules(rules))
        return 0

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
