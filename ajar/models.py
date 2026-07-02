"""Core data structures shared across the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Ordered severities. Higher value == more serious."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.rank >= other.rank


@dataclass(frozen=True)
class Rule:
    """A single detection rule, loaded from a transparent YAML file."""

    id: str
    name: str
    severity: Severity
    category: str
    message: str
    pattern: str
    # Educational fields — the reason ajar exists is to teach, not just flag.
    why: str = ""
    fix: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)
    # File selection: glob-style suffixes this rule applies to (e.g. ".py").
    # Empty means "any text file".
    extensions: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Finding:
    """One matched issue in a file."""

    rule: Rule
    path: str
    line: int
    column: int
    evidence: str

    def fingerprint(self) -> str:
        """A stable id for baseline diffing.

        Intentionally excludes the line number so that unrelated edits above a
        finding do not make it look "new". Based on rule id, file path, and the
        matched code.
        """
        import hashlib

        norm_path = self.path.replace("\\", "/")
        raw = f"{self.rule.id}|{norm_path}|{self.evidence}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "name": self.rule.name,
            "severity": self.rule.severity.value,
            "category": self.rule.category,
            "message": self.rule.message,
            "why": self.rule.why,
            "fix": self.rule.fix,
            "references": list(self.rule.references),
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint(),
        }
