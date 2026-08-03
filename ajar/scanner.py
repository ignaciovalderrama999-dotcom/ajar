"""The scanning engine: walk files, apply rules, collect findings."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import replace
from fnmatch import fnmatch
from pathlib import Path

from .entropy import ENTROPY_RULE, find_high_entropy
from .models import Finding, Rule
from .parsing import analyze
from .rules import compile_rules
from .taint import TAINT_RULE, find_taint_flows

# Directories we never descend into — build output and tooling, not source.
# Scanning a build/output dir (its bundled, minified vendor code) is the biggest
# source of false positives, so these are excluded by default rather than
# trusting the user to point at the right folder.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "__pycache__",
    ".venv", "venv", "env", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "out", "coverage", ".tox", ".idea", ".vscode",
    "site-packages", ".next", ".nuxt", ".svelte-kit", ".output", ".cache",
    ".parcel-cache", ".turbo", ".angular", ".serverless", "target", "vendor",
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

# Minified / bundled files are machine-generated vendor code: a single line can
# be tens of thousands of characters, and pattern rules fire constantly on the
# packed syntax (the classic false "critical SQL injection" inside a library
# bundle). Skip them by name or by the tell-tale very-long line.
_MINIFIED_NAME_RE = re.compile(r"\.(min|bundle|chunk|vendor)\.(js|css|mjs|cjs)$", re.IGNORECASE)
_MINIFIED_LINE_LEN = 2000


def _looks_minified(name: str, text: str) -> bool:
    if _MINIFIED_NAME_RE.search(name):
        return True
    # A newline scan is cheap and avoids building a huge splitlines() list.
    longest = max((len(seg) for seg in text.split("\n")), default=0)
    return longest > _MINIFIED_LINE_LEN

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

        if _looks_minified(file_path.name, text):
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

    # Taint analysis (data-flow): user input flowing into a dangerous sink,
    # possibly several lines away — exploitable flows per-line patterns can't see.
    all_lines = text.splitlines()
    for tlineno, tcol, label, var in find_taint_flows(all_lines):
        tline = all_lines[tlineno - 1]
        ignored = _ignored_rule_ids(tline)
        if ignored is not None and (not ignored or TAINT_RULE.id in ignored):
            continue
        if regions is not None and regions.in_comment(tlineno - 1, len(tline[:tcol].encode("utf-8"))):
            continue
        yield Finding(
            rule=replace(TAINT_RULE, message=f"User input reaches {label} through variable '{var}'."),
            path=display_path,
            line=tlineno,
            column=tcol + 1,
            evidence=tline.strip()[:200],
        )
