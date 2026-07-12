"""Lightweight taint analysis: follow user input to a dangerous sink.

Single-line pattern rules miss the most common *real* injection: user input is
stored in a variable, then that variable is used in a dangerous operation a few
lines later. This module does a small intra-file data-flow pass — find variables
assigned from a user-controlled source, propagate through simple assignments,
then flag dangerous sinks that use those variables.

It is our own heuristic implementation (not a full dataflow engine), tuned to
stay quiet on safe code. It runs on top of the pattern rules, catching flows
they cannot see.
"""

from __future__ import annotations

import re

from .models import Rule, Severity

# Built-in rule for taint analysis (data-flow, not a regex pattern): user input
# tracked across variables into a dangerous sink.
TAINT_RULE = Rule(
    id="TAINT_USER_INPUT_TO_SINK",
    name="User input flows into a dangerous operation",
    severity=Severity.HIGH,
    category="injection",
    message="User input reaches a dangerous operation through a variable.",
    pattern="",  # handled by the taint engine, not regex
    why=(
        "A value taken from the request is stored in a variable and later used "
        "in a sensitive operation without visible sanitization — a real, "
        "exploitable injection path that single-line pattern rules cannot see."
    ),
    fix=(
        "Sanitize or parameterize the value at the sink: parameterized queries "
        "for SQL, argument lists (no shell) for commands, escaping/DOMPurify for "
        "HTML, allow-listing for file paths and outbound URLs."
    ),
    references=("https://owasp.org/Top10/A03_2021-Injection/",),
    context="any",
)

# `name = <expr>`  (optionally with const/let/var/val)
_ASSIGN_RE = re.compile(r"^\s*(?:const|let|var|final|val)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$")

# things that produce user-controlled input. `\.searchParams\b` (a property
# access) is deliberately narrower than the bare word "searchParams" so that
# building a *new* URLSearchParams() (a generic query-string builder, not a
# request source) is not mistaken for tainted input.
_SOURCE_RE = re.compile(
    r"(?i)(request\.|req\.|\.args\b|\.query\b|\.params\b|\.body\b|\.searchParams\b"
    r"|(req|request)\.(headers|cookies)\b|\binput\s*\(|sys\.argv|process\.argv"
    r"|request\.form|get_json|request\.data|params\[|formData\.get"
    r"|\$_(GET|POST|REQUEST|COOKIE)\b|\bgetParameter\s*\(|\bgetHeader\s*\()"
)

# functions that neutralize user input — if the value passes through one of
# these, the flow is considered safe and is not reported.
_SANITIZER_RE = re.compile(
    r"(?i)\b(int|float|bool|escape|html\.escape|markupsafe\.escape|sanitize|"
    r"clean|bleach\.clean|DOMPurify|validate|quote|shlex\.quote|"
    r"parameterize|encodeURIComponent|encodeURI|Number|parseInt|parseFloat)\s*\("
)

# dangerous sinks: (regex, human label)
_SINKS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(execute|executemany|executescript|raw)\s*\("), "a SQL query (SQL injection)"),
    (re.compile(r"(?i)(\.|->)query\s*\("), "a SQL query (SQL injection)"),
    (re.compile(r"(?i)(^|[^.\w])(eval|exec)\s*\("), "dynamic code execution (RCE)"),
    (re.compile(r"(?i)new\s+Function\s*\("), "dynamic code execution (RCE)"),
    (re.compile(r"(?i)os\.system\s*\("), "a shell command (command injection)"),
    (re.compile(r"(?i)subprocess\.\w+\("), "a subprocess call (command injection)"),
    (re.compile(r"(?i)\.(inner|outer)HTML\s*="), "the page HTML (XSS)"),
    (re.compile(r"(?i)document\.write(ln)?\s*\("), "the page HTML (XSS)"),
    (re.compile(r"(?i)\bopen\s*\("), "a file path (path traversal)"),
    (re.compile(r"(?i)pickle\.loads?\s*\("), "deserialization (RCE)"),
    (re.compile(r"(?i)(fetch|requests\.\w+|urlopen)\s*\("), "an outbound request (SSRF)"),
    (re.compile(r"(?i)\b(res|response)\.(send|write|end)\s*\("), "an HTTP response (reflected XSS)"),
    (re.compile(r"(?i)\bredirect\s*\("), "a redirect (open redirect)"),
]

# Sinks whose same-origin literal ("/path...") is not the dangerous case: an
# outbound request or a redirect to a fixed relative path has a fixed host.
_SAME_ORIGIN_SAFE_LABELS = ("an outbound request", "a redirect")

# A literal same-origin path right at the call, e.g. fetch("/api/x"...): the
# host is fixed, so tainted query params appended after it are not SSRF.
_SAME_ORIGIN_RE = re.compile(r"""^\s*['"`]/""")


def _word_in(name: str, text: str) -> bool:
    # Treat `$` as part of an identifier so PHP variables ($id) match at their
    # real boundaries — a plain \b fails against the leading `$`.
    return (
        re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", text) is not None
    )


def find_taint_flows(lines: list[str]):
    """Yield (lineno, column, sink_label, variable) for input reaching a sink.

    ``lineno`` is 1-indexed; ``column`` is 0-indexed into the line.
    """
    tainted: set[str] = set()
    # Collect tainted variables and propagate through simple assignments.
    for _ in range(3):  # a few passes so a = b; b = input() converges
        before = len(tainted)
        for line in lines:
            m = _ASSIGN_RE.match(line)
            if not m:
                continue
            name, rhs = m.group(1), m.group(2)
            # A value that passes through a sanitizer is considered clean, and it
            # also cleanses the variable it is assigned to.
            if _SANITIZER_RE.search(rhs):
                tainted.discard(name)
                continue
            if _SOURCE_RE.search(rhs) or any(_word_in(t, rhs) for t in tainted):
                tainted.add(name)
        if len(tainted) == before:
            break

    if not tainted:
        return

    seen: set[tuple[int, str]] = set()
    for i, line in enumerate(lines):
        assign = _ASSIGN_RE.match(line)
        for sink_re, label in _SINKS:
            sm = sink_re.search(line)
            if not sm:
                continue
            # a tainted variable used in the sink's arguments (after the sink name)
            args = line[sm.start():]
            used = next((t for t in sorted(tainted) if _word_in(t, args)), None)
            if not used:
                continue
            # the value is sanitized right at the sink, e.g. execute(int(uid))
            if _SANITIZER_RE.search(args):
                continue
            # a same-origin relative URL literal: only the query string is
            # tainted, the host is fixed — not an SSRF-shaped flow
            if label.startswith("an outbound request") and _SAME_ORIGIN_RE.match(args):
                continue
            # skip the line that merely assigns the taint (that's the source, not a sink use)
            if assign and assign.group(1) == used and sink_re.search(assign.group(2) or "") is None:
                continue
            key = (i + 1, used)
            if key in seen:
                continue
            seen.add(key)
            yield i + 1, sm.start(), label, used
            break
