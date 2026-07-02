"""Render findings for humans (terminal) and machines (JSON).

The terminal output is deliberately educational: every finding explains the
attacker's angle and the fix. That is the whole point of ajar.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from collections.abc import Sequence

from .models import Finding, Rule, Severity

_COLORS = {
    Severity.CRITICAL: "\033[95m",  # magenta
    Severity.HIGH: "\033[91m",      # red
    Severity.MEDIUM: "\033[93m",    # yellow
    Severity.LOW: "\033[96m",       # cyan
    Severity.INFO: "\033[90m",      # grey
}
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_FOOTER = (
    "ajar is a defensive aid, not a security guarantee. Scan only code you own "
    "or are authorized to review. Provided AS IS, no warranty — see DISCLAIMER.md."
)


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def render_terminal(findings: Sequence[Finding], scanned_root: str) -> str:
    color = _use_color()
    lines: list[str] = []

    banner = _c("ajar", _BOLD, color) + _c("  the door you left open by default", _DIM, color)
    lines.append("")
    lines.append(banner)
    lines.append(_c(f"scanned: {scanned_root}", _DIM, color))
    lines.append("")

    if not findings:
        lines.append(_c("  No open doors found. ", "\033[92m", color) + _c("(that we know of — keep your rules updated)", _DIM, color))
        lines.append("")
        lines.append(_c(_FOOTER, _DIM, color))
        lines.append("")
        return "\n".join(lines)

    for f in findings:
        sev = f.rule.severity
        tag = _c(f" {sev.value.upper()} ", _COLORS[sev] + _BOLD, color)
        location = _c(f"{f.path}:{f.line}:{f.column}", _BOLD, color)
        lines.append(f"{tag} {location}")
        lines.append(f"   {_c(f.rule.name, _BOLD, color)}  {_c('[' + f.rule.id + ']', _DIM, color)}")
        lines.append(f"   {f.rule.message}")
        lines.append(f"   {_c('code:', _DIM, color)} {f.evidence}")
        if f.rule.why:
            lines.append(f"   {_c('why: ', _BOLD, color)}{f.rule.why}")
        if f.rule.fix:
            lines.append(f"   {_c('fix: ', _BOLD, color)}{f.rule.fix}")
        if f.rule.references:
            for ref in f.rule.references:
                lines.append(f"   {_c('ref: ', _DIM, color)}{_c(ref, _DIM, color)}")
        lines.append("")

    lines.append(_render_summary(findings, color))
    lines.append("")
    lines.append(_c(_FOOTER, _DIM, color))
    lines.append("")
    return "\n".join(lines)


def _render_summary(findings: Sequence[Finding], color: bool) -> str:
    counts = Counter(f.rule.severity for f in findings)
    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts.get(sev):
            parts.append(_c(f"{counts[sev]} {sev.value}", _COLORS[sev] + _BOLD, color))
    total = len(findings)
    header = _c(f"Found {total} open door{'s' if total != 1 else ''}:", _BOLD, color)
    return f"{header} " + _c(" · ", _DIM, color).join(parts)


def render_json(findings: Sequence[Finding], scanned_root: str) -> str:
    payload = {
        "tool": "ajar",
        "scanned": scanned_root,
        "summary": {
            "total": len(findings),
            "by_severity": {
                sev.value: sum(1 for f in findings if f.rule.severity is sev)
                for sev in Severity
            },
        },
        "findings": [f.as_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def render_markdown_rules(rules: Sequence[Rule]) -> str:
    """Render the full rule catalog as Markdown (used to generate RULES.md)."""

    by_category: dict[str, list[Rule]] = {}
    for rule in rules:
        by_category.setdefault(rule.category, []).append(rule)

    lines: list[str] = []
    lines.append("# ajar rule catalog")
    lines.append("")
    lines.append(
        f"ajar ships **{len(rules)} rules** across **{len(by_category)} categories**. "
        "Every rule explains the risk and the fix. Rules are plain YAML in "
        "[`ajar/rules/`](ajar/rules/) — audit or extend them freely."
    )
    lines.append("")
    lines.append("> Regenerate this file with: `ajar rules --format md > RULES.md`")
    lines.append("")

    for category in sorted(by_category):
        cat_rules = sorted(by_category[category], key=lambda r: (-r.severity.rank, r.id))
        lines.append(f"## {category}  ({len(cat_rules)})")
        lines.append("")
        for rule in cat_rules:
            lines.append(f"### `{rule.id}` — {rule.name}")
            lines.append("")
            lines.append(f"**Severity:** {rule.severity.value}")
            lines.append("")
            lines.append(rule.message)
            lines.append("")
            if rule.why:
                lines.append(f"- **Why it matters:** {rule.why}")
            if rule.fix:
                lines.append(f"- **How to fix:** {rule.fix}")
            for ref in rule.references:
                lines.append(f"- **Reference:** {ref}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_sarif(findings: Sequence[Finding], scanned_root: str) -> str:
    """Minimal SARIF 2.1.0 output so ajar plugs into GitHub code scanning."""

    rules_seen = {}
    results = []
    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    for f in findings:
        rules_seen.setdefault(
            f.rule.id,
            {
                "id": f.rule.id,
                "name": f.rule.name,
                "shortDescription": {"text": f.rule.message},
                "helpUri": f.rule.references[0] if f.rule.references else None,
            },
        )
        results.append(
            {
                "ruleId": f.rule.id,
                "level": level_map[f.rule.severity],
                "message": {"text": f.rule.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path.replace("\\", "/")},
                            "region": {"startLine": f.line, "startColumn": f.column},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ajar",
                        "informationUri": "https://github.com/your-username/ajar",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
