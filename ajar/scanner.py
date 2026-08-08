"""The scanning engine: walk files, apply rules, collect findings."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import replace
from fnmatch import fnmatch
from pathlib import Path

from .entropy import ENTROPY_RULE, find_high_entropy
from .models import Finding, Rule, Severity
from .parsing import analyze
from .project import find_project_findings
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
    # Translation/localization data: strings for humans, not code — a huge
    # source of entropy/secret false positives and never a place bugs live.
    "i18n", "locales", "locale", "translations", "lang", "langs",
}

# Only scan files that plausibly hold code or config.
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".php",
    ".cs", ".c", ".cpp", ".rs", ".sh", ".bash", ".yml", ".yaml", ".toml",
    ".ini", ".cfg", ".conf", ".env", ".json", ".tf", ".tfvars", ".xml",
    ".properties", ".gradle", ".dockerfile",
    # Web asset files — where CSP domains and other usage actually live, so the
    # cross-file config check can see them (and vulns can hide here too).
    ".html", ".htm", ".vue", ".svelte", ".astro", ".css", ".scss", ".sass", ".less",
}
TEXT_FILENAMES = {"Dockerfile", ".env", "Makefile"}

# Dependency lock files: machine-generated, full of public integrity checksums
# (sha512-… hashes) that trip entropy/secret rules. They are the single biggest
# source of noise on a real project — never source, never a place bugs live.
SKIP_FILENAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "composer.lock", "Cargo.lock", "poetry.lock", "Pipfile.lock",
    "pdm.lock", "Gemfile.lock", "go.sum", "flake.lock",
}

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


# A gitignore pattern that would hide an .env file — dropped so the env-key
# analysis still runs (projects routinely gitignore .env, but a security tool
# still wants to inspect it).
_ENV_IGNORE_RE = re.compile(r"(^|/)\.env(\.|\*|$)")


def _load_ignore_patterns(root: Path) -> tuple[str, ...]:
    """Honor the project's own ignore lists (.gitignore, .vercelignore) so ajar
    does not report findings in files the project excludes/does not deploy.

    Patterns that would hide .env files are dropped (we always want to scan those
    for secrets and unused keys).
    """
    patterns: list[str] = []
    for fn in (".gitignore", ".vercelignore"):
        p = root / fn
        if not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue  # blank, comment, or a negation (un-ignore) — skip
            line = line.lstrip("/").rstrip("/")
            if not line or _ENV_IGNORE_RE.search("/" + line):
                continue
            patterns.append(line)
    return tuple(patterns)


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
        if path.name in SKIP_FILENAMES:
            continue
        if excludes and _is_excluded(path, excludes):
            continue
        if (
            path.name in TEXT_FILENAMES
            or path.suffix.lower() in TEXT_EXTENSIONS
            or path.name.startswith(".env")  # .env.local, .env.production, …
        ):
            yield path


# Test / fixture files legitimately contain fake credentials, tokens, and seed
# passwords — the #1 source of secret false positives. In these files we suppress
# the two *heuristic* secret detectors (generic "password = ..." assignments and
# entropy) but KEEP specific vendor-format keys (AWS/Stripe/…), which are almost
# always a real leak even in a test.
_TEST_PATH_SEGMENTS = {
    "test", "tests", "spec", "specs", "e2e", "cypress", "__tests__",
    "__mocks__", "mocks", "fixtures", "fixture", "testdata", "test-data",
}
_TEST_FILE_RE = re.compile(r"\.(test|spec)\.[cm]?[jt]sx?$", re.IGNORECASE)


def _is_test_file(path: Path) -> bool:
    if _TEST_FILE_RE.search(path.name):
        return True
    return any(part.lower() in _TEST_PATH_SEGMENTS for part in path.parts)


def _is_heuristic_secret(rule: Rule) -> bool:
    """A low-confidence secret detector (generic assignment), as opposed to a
    specific vendor key pattern."""
    return rule.category == "secrets" and "GENERIC" in rule.id


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


# A Firebase web config: its apiKey (AIza…) is a PUBLIC identifier by design.
_FIREBASE_CTX_RE = re.compile(r"firebaseConfig|initializeApp|authDomain")
_INNERHTML_VAR_RE = re.compile(r"(\w+)\s*\.\s*(?:inner|outer)HTML\s*=")
# innerHTML content that goes into these elements parses as text, not markup —
# a <script> inside is inert. The textarea idiom is the standard entity-decoder.
_SAFE_HTML_ELEMS = ("textarea", "title", "script", "style")


def _refine_findings(
    findings: list[Finding], file_texts: dict[Path, str]
) -> list[Finding]:
    """Post-process for precision: drop duplicate secret hits on one line, treat a
    Firebase web apiKey as public, and clear innerHTML into a text-only element."""
    text_by_path = {str(p): t for p, t in file_texts.items()}
    line_cache: dict[str, list[str]] = {}

    def line_at(path: str, lineno: int) -> str:
        if path not in line_cache:
            line_cache[path] = text_by_path.get(path, "").splitlines()
        ls = line_cache[path]
        return ls[lineno - 1] if 0 <= lineno - 1 < len(ls) else ""

    # A generic secret and a specific vendor secret on the SAME line are the same
    # finding — keep the specific one only.
    drop: set[int] = set()
    groups: dict[tuple[str, int], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.path, f.line), []).append(f)
    for group in groups.values():
        if len(group) < 2:
            continue
        if any(f.rule.category == "secrets" and "GENERIC" not in f.rule.id for f in group):
            for f in group:
                if "GENERIC" in f.rule.id:
                    drop.add(id(f))

    refined: list[Finding] = []
    for f in findings:
        if id(f) in drop:
            continue
        if f.rule.id == "XSS_INNERHTML":
            m = _INNERHTML_VAR_RE.search(line_at(f.path, f.line))
            var = m.group(1) if m else ""
            text = text_by_path.get(f.path, "")
            if var.lower() in _SAFE_HTML_ELEMS:
                continue
            # a variable built as one of the safe elements: createElement('textarea')
            if var and re.search(
                r"\b" + re.escape(var) + r"\b\s*=\s*[^;\n]*createElement\(\s*['\"]"
                r"(?:" + "|".join(_SAFE_HTML_ELEMS) + r")['\"]",
                text,
            ):
                continue
        if f.rule.id == "SECRET_GOOGLE_API_KEY" and _FIREBASE_CTX_RE.search(
            text_by_path.get(f.path, "")
        ):
            f = replace(
                f,
                rule=replace(
                    f.rule,
                    severity=Severity.MEDIUM,
                    message=f.rule.message
                    + " (Firebase web key: public by design — verify it is not a server-side key.)",
                ),
            )
        refined.append(f)
    return refined


def scan_path(
    root: Path,
    rules: Iterable[Rule],
    excludes: tuple[str, ...] = (),
) -> list[Finding]:
    """Scan a file or directory tree and return all findings."""

    compiled = compile_rules(rules)
    findings: list[Finding] = []
    # Collected for the cross-file, project-level pass (see ajar.project).
    file_texts: dict[Path, str] = {}
    # Honor the project's own ignore lists so we don't report on excluded files.
    if root.is_dir():
        excludes = excludes + _load_ignore_patterns(root)

    for file_path in _iter_files(root, excludes):
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, ValueError):
            continue

        if _looks_minified(file_path.name, text):
            continue

        file_texts[file_path] = text
        findings.extend(_scan_text(file_path, text, compiled))

    # Project-level analysis needs the whole repo at once (config vs. real usage).
    findings.extend(find_project_findings(file_texts))

    # Precision pass: dedup, Firebase-public downgrade, safe-element innerHTML.
    findings = _refine_findings(findings, file_texts)

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
    # In test/fixture files, fake credentials are the norm — suppress the
    # heuristic secret detectors there (but keep specific vendor-key patterns).
    is_test = _is_test_file(file_path)

    for lineno, line in enumerate(text.splitlines(), start=1):
        suppressed = _ignored_rule_ids(line)
        line_has_secret = False
        for rule, pattern in compiled:
            if not _rule_applies(rule, file_path):
                continue
            if is_test and _is_heuristic_secret(rule):
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
        # the match is not inside a comment, and this is not a test/fixture file
        # (entropy is a heuristic detector, suppressed there like generic secrets).
        if line_has_secret or is_test:
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
