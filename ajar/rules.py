"""Load transparent, human-readable rules from bundled YAML files.

Rules live in ``ajar/rules/*.yml`` so anyone can audit exactly what ajar
looks for. No hidden logic, no phone-home.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

import yaml

from .models import Rule, Severity

RULES_DIR = Path(__file__).parent / "rules"


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


def _parse_rule(raw: dict, source: Path) -> Rule:
    try:
        severity = Severity(str(raw["severity"]).lower())
    except (KeyError, ValueError) as exc:
        raise RuleError(f"{source.name}: invalid or missing severity in rule {raw.get('id')!r}") from exc

    for required in ("id", "name", "message", "pattern", "category"):
        if not raw.get(required):
            raise RuleError(f"{source.name}: rule {raw.get('id')!r} missing required field {required!r}")

    pattern = str(raw["pattern"])
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RuleError(f"{source.name}: rule {raw['id']!r} has an invalid regex: {exc}") from exc

    return Rule(
        id=str(raw["id"]),
        name=str(raw["name"]),
        severity=severity,
        category=str(raw["category"]),
        message=str(raw["message"]),
        pattern=pattern,
        why=str(raw.get("why", "")).strip(),
        fix=str(raw.get("fix", "")).strip(),
        references=tuple(raw.get("references", []) or ()),
        extensions=tuple(raw.get("extensions", []) or ()),
    )


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    """Load and validate every rule from the rules directory."""

    directory = rules_dir or RULES_DIR
    rules: list[Rule] = []
    seen_ids: set[str] = set()

    for path in sorted(directory.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in data.get("rules", []) or []:
            rule = _parse_rule(raw, path)
            if rule.id in seen_ids:
                raise RuleError(f"duplicate rule id {rule.id!r} in {path.name}")
            seen_ids.add(rule.id)
            rules.append(rule)

    if not rules:
        raise RuleError(f"no rules found in {directory}")
    return rules


def compile_rules(rules: Iterable[Rule]) -> list[tuple[Rule, re.Pattern[str]]]:
    """Pre-compile rule patterns for scanning."""

    return [(rule, re.compile(rule.pattern)) for rule in rules]
