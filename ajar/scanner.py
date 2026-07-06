"""The scanning engine: walk files, apply rules, collect findings."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from fnmatch import fnmatch
from pathlib import Path

from .entropy import find_high_entropy
from .models import Finding, Rule, Severity
from .parsing import analyze
from .rules import compile_rules

# Built-in rule for entropy-based detection (not a YAML regex rule, since it
# needs to measure randomness rather than match a pattern).
ENTROPY_RULE = Rule(
    id="SECRET_HIGH_ENTROPY",
    name="High-entropy string (possible hardcoded secret)",
    severity=Severity.MEDIUM,
    category="secrets",
    message="A random-looking string may be a hardcoded secret or token.",
    pattern="",  # handled by the entropy engine, not regex
    why=(
        "Random, high-entropy strings in source are often API keys, tokens, or "
        "passwords that match no known vendor pattern — so pattern scanners miss "
        "them, but attackers scraping repos do not."
    ),
    fix=(
        "If this is a secret, move it to an environment variable or a secrets "
        "manager and rotate it. If it is not a secret (a hash, an id), silence it "
        "with a trailing  # ajar:ignore SECRET_HIGH_ENTROPY  comment."
    ),
    references=("https://cwe.mitre.org/data/definitions/798.html",),
    context="any",
)

# Directories we never descend into — noise, not source.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".mypy_cache", ".pytest_cache", "dist", "build", ".tox", ".idea",
    ".vscode", "site-packages", ".next", "target", "vendor",
}

# Only scan files that plausibly hold code or config.
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".php",
    ".cs", ".c", ".cpp", ".rs", ".sh", ".bash", ".yml", ".yaml", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".json", ".tf", ".tfvars", ".xml",
    ".properties", ".gradle", ".dockerfile",
}
TEXT_FILENAMES = {"Dockerfile", ".env", "Makefile"}

MAX_FILE_BYTES = 2_000_000  # skip anything larger than ~2 MB

# Inline suppression: put "ajar:ignore" (optionally "ajar:ignore RULE_ID")
# on a line to silence findings on it.
_IGNORE_RE = re.compile(r"ajar:ignore(?:\s+([A-Za-z0-9_,\-]+))?")


def _is_excluded(path: Path, excludes: tuple[str, ...]) -> bool:
    """True if the path matches any user-supplied exclude glob.

    A pattern matches when it matches the full posix path, or a trailing part of
    it, or any single path component (so ``rules``, ``*.yml`` and
    ``ajar/rules/*`` all work as expected).
    """
    posix = path.as_posix()
    for pattern in excludes:
        if fnmatch(posix, pattern) or fnmatch(posix, f"*/{pattern}"):
            return True
        if any(fnmatch(part, pattern) for part in path.parts):
            return True
    return False


def _iter_files(root: Path, excludes: tuple[str, ...] = ()) -> Iterator[Path]:
    if root.is_file():
        if not _is_excluded(root, excludes):
            yield root
        return
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if excludes and _is_excluded(path, excludes):
            continue
        if path.name in TEXT_FILENAMES or path.suffix.lower() in TEXT_EXTENSIONS:
            yield path


def _rule_applies(rule: Rule, path: Path) -> bool:
    if not rule.extensions:
        return True
    suffix = path.suffix.lower()
    name = path.name
    return suffix in rule.extensions or name in rule.extensions


def _ignored_rule_ids(line: str) -> set[str] | None:
    """Return the set of rule ids suppressed on a line.

    ``None`` -> nothing suppressed. Empty set -> suppress everything.
    """
    match = _IGNORE_RE.search(line)
    if not match:
        return None
    ids = match.group(1)
    if not ids:
        return set()  # bare ajar:ignore -> suppress all rules on this line
    return {rid.strip() for rid in ids.split(",") if rid.strip()}


def scan_path(
    root: Path,
    rules: Iterable[Rule],
    excludes: tuple[str, ...] = (),
) -> list[Finding]:
    """Scan a file or directory tree and return all findings."""

    compiled = compile_rules(rules)
    findings: list[Finding] = []

    for file_path in _iter_files(root, excludes):
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, ValueError):
            continue

        findings.extend(_scan_text(file_path, text, compiled))

    findings.sort(key=lambda f: (-f.rule.severity.rank, f.path, f.line))
    return findings


def _scan_text(
    file_path: Path,
    text: str,
    compiled: list[tuple[Rule, re.Pattern[str]]],
) -> Iterator[Finding]:
    display_path = str(file_path)
    # Structural analysis (comment/string regions) when tree-sitter is available
    # for this language; otherwise None -> plain pattern scanning.
    regions = analyze(text, file_path.suffix)

    for lineno, line in enumerate(text.splitlines(), start=1):
        suppressed = _ignored_rule_ids(line)
        line_has_secret = False
        for rule, pattern in compiled:
            if not _rule_applies(rule, file_path):
                continue
            if suppressed is not None and (not suppressed or rule.id in suppressed):
                continue
            match = pattern.search(line)
            if not match:
                continue
            # Structural context: a "code" rule is ignored inside comments and
            # strings; a "string" rule is ignored only in comments (it targets
            # string content, e.g. a regex); an "any" rule is never suppressed.
            if regions is not None:
                ctx = rule.effective_context
                if ctx != "any":
                    byte_col = len(line[: match.start()].encode("utf-8"))
                    row = lineno - 1
                    if regions.in_comment(row, byte_col):
                        continue
                    if ctx == "code" and regions.in_string(row, byte_col):
                        continue
            if rule.category == "secrets":
                line_has_secret = True
            yield Finding(
                rule=rule,
                path=display_path,
                line=lineno,
                column=match.start() + 1,
                evidence=line.strip()[:200],
            )

        # Entropy-based secret detection. Only if no known-pattern secret already
        # matched this line (avoids double-reporting), the rule isn't suppressed,
        # and the match is not inside a comment.
        if line_has_secret:
            continue
        if suppressed is not None and (not suppressed or ENTROPY_RULE.id in suppressed):
            continue
        for col, _value in find_high_entropy(line):
            if regions is not None and regions.in_comment(lineno - 1, len(line[:col].encode("utf-8"))):
                continue
            yield Finding(
                rule=ENTROPY_RULE,
                path=display_path,
                line=lineno,
                column=col + 1,
                evidence=line.strip()[:200],
            )
            break  # one entropy finding per line is enough
