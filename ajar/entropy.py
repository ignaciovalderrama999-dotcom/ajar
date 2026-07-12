"""High-entropy string detection: catch secrets that match no known pattern.

Many real leaks are random tokens that don't fit a vendor pattern (AWS, Stripe,
etc.). The industry-standard way to catch them is Shannon entropy — a random
token has much higher entropy than ordinary text. This is our own, independent
implementation of that public algorithm; no third-party code is used.
"""

from __future__ import annotations

import math
import re

from .models import Rule, Severity

# quoted string literals between 20 and 120 chars (secrets live in that range)
_STRING_RE = re.compile(r"""(['"])([^'"\n\\]{20,120})\1""")

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

# a file path/asset reference: has a path separator and ends in a short
# extension, e.g. "/components/cart_DASHBOARD_V10.html" or "./assets/logo.png".
# These often mix case and digits like a real secret, but are not one.
_PATH_RE = re.compile(r"^\.{0,2}/?[\w.\-]+(/[\w.\-]+)*\.[A-Za-z0-9]{1,5}$")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character (0 = uniform, higher = more random)."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_token(value: str) -> bool:
    """Random credentials mix cases and digits; prose and paths do not."""
    if " " in value:
        return False  # prose, not a token
    if "/" in value and _PATH_RE.match(value):
        return False  # a file path / asset reference, not a secret
    has_lower = any(c.islower() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    # a token is a mixed-class blob, or a long hex/base64 run
    mixed = has_lower and has_upper and has_digit
    hexish = bool(re.fullmatch(r"[0-9a-fA-F]{32,}", value))
    return mixed or hexish


def find_high_entropy(line: str, threshold: float = 4.0):
    """Yield (column, value) for quoted strings that look like a secret.

    ``column`` is 0-indexed into ``line`` (start of the string's contents).
    """
    for match in _STRING_RE.finditer(line):
        value = match.group(2)
        if "://" in value:
            continue  # a URL, handled by other rules
        if not _looks_like_token(value):
            continue
        if shannon_entropy(value) >= threshold:
            yield match.start(2), value
