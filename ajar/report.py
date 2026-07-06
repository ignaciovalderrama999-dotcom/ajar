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
from datetime import date

from . import __version__
from .models import Finding, Rule, Severity

# How much each finding subtracts from a perfect 100 when grading a project.
_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

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


def _grade(findings: Sequence[Finding]) -> tuple[str, int]:
    """Return a letter grade and a 0-100 score from the findings."""
    penalty = sum(_SEVERITY_WEIGHT[f.rule.severity] for f in findings)
    score = max(0, 100 - penalty)
    if not findings:
        return "A+", 100
    for cutoff, letter in [(90, "A"), (80, "B"), (70, "C"), (60, "D")]:
        if score >= cutoff:
            return letter, score
    return "F", score


def render_report(findings: Sequence[Finding], scanned_root: str) -> str:
    """A professional Markdown security-audit report with a grade."""
    grade, score = _grade(findings)
    counts = Counter(f.rule.severity for f in findings)
    by_category = Counter(f.rule.category for f in findings)
    crit = counts.get(Severity.CRITICAL, 0)
    high = counts.get(Severity.HIGH, 0)

    if not findings:
        verdict = "No issues detected by automated analysis. This is a strong signal, not a guarantee."
    elif crit:
        verdict = f"**Action required.** {crit} critical issue(s) can likely be exploited directly — fix these first."
    elif high:
        verdict = f"**Needs attention.** {high} high-severity issue(s) represent real risk under the right conditions."
    else:
        verdict = "Mostly hardening and defense-in-depth items — no critical/high exposure found."

    out: list[str] = []
    out.append("# 🔒 Security Audit Report")
    out.append("")
    out.append(f"**Project:** `{scanned_root}`  ")
    out.append(f"**Date:** {date.today().isoformat()}  ")
    out.append(f"**Tool:** ajar v{__version__} (defensive static analysis)")
    out.append("")
    out.append(f"## Security grade: {grade}  ({score}/100)")
    out.append("")
    out.append(verdict)
    out.append("")

    out.append("## Summary")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts.get(sev):
            out.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value} | {counts[sev]} |")
    out.append(f"| **Total** | **{len(findings)}** |")
    out.append("")
    if by_category:
        cats = " · ".join(f"{cat} ({n})" for cat, n in by_category.most_common())
        out.append(f"**By category:** {cats}")
        out.append("")

    if findings:
        out.append("## Findings")
        out.append("")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            group = [f for f in findings if f.rule.severity is sev]
            if not group:
                continue
            out.append(f"### {_SEVERITY_EMOJI[sev]} {sev.value.capitalize()} ({len(group)})")
            out.append("")
            for f in group:
                out.append(f"- **{f.rule.name}** — `{f.path}:{f.line}`  ")
                out.append(f"  `{f.evidence}`  ")
                if f.rule.why:
                    out.append(f"  *Why:* {f.rule.why}  ")
                if f.rule.fix:
                    out.append(f"  *Fix:* {f.rule.fix}")
                out.append("")

        out.append("## Prioritized remediation")
        out.append("")
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        step = 1
        for sev in order:
            n = counts.get(sev, 0)
            if n:
                out.append(f"{step}. Fix the **{n} {sev.value}** finding(s) — {_SEVERITY_EMOJI[sev]} start here." if step == 1 else f"{step}. Then address the **{n} {sev.value}** finding(s).")
                step += 1
        out.append("")

    out.append("---")
    out.append("")
    out.append(
        "> ajar is a defensive static-analysis aid. A clean report is a strong result, "
        "not a guarantee — business-logic and design flaws need a human review, and "
        "anything critical warrants a professional audit."
    )
    return "\n".join(out) + "\n"


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
                        "informationUri": "https://github.com/ignaciovalderrama999-dotcom/ajar",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
