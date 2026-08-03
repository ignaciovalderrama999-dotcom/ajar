"""Project-level, cross-file analysis.

Unlike the per-line rules, these checks need the **whole repository** in view.
They answer questions a single line never can — "is this .env key used anywhere?",
"is this domain allow-listed in the CSP but referenced nowhere in the code?".

This is the mechanical, deterministic half of a cross-file audit: no reasoning,
just cross-referencing declared config against real usage. It is exactly the kind
of finding a line-by-line scanner (and a careless reviewer) miss, and it does not
depend on an LLM remembering to check it.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, Rule, Severity

# --------------------------------------------------------------- env variables

# .env, .env.local, .env.production … but NOT templates (.env.example/.sample).
_ENV_FILE_RE = re.compile(r"^\.env(\.[\w.-]+)?$")
_ENV_TEMPLATE_RE = re.compile(r"\.(example|sample|template|dist)$", re.IGNORECASE)
_ENV_KEY_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")

# Prefixes whose values are compiled into the client bundle and shipped to the
# browser — an unused one is exposed for no reason at all.
_PUBLIC_PREFIXES = (
    "NEXT_PUBLIC_", "VITE_", "REACT_APP_", "PUBLIC_", "EXPO_PUBLIC_",
    "GATSBY_", "NUXT_PUBLIC_",
)

UNUSED_ENV_KEY = Rule(
    id="UNUSED_ENV_KEY",
    name="Environment variable defined but never used",
    severity=Severity.LOW,
    category="insecure-defaults",
    message="This .env key is not referenced anywhere in the code.",
    pattern="",
    why=(
        "A key defined in .env but referenced nowhere is dead configuration — "
        "usually left over from a removed integration. It is clutter that hides "
        "which secrets are actually live, and if it was ever a real credential it "
        "is still sitting in the file."
    ),
    fix=(
        "Remove the unused key from the .env file. If it was ever a real secret, "
        "rotate it as well. If it is used dynamically (e.g. process.env[name]), "
        "silence this with a trailing '# ajar:ignore' on the line."
    ),
    references=("https://cwe.mitre.org/data/definitions/1188.html",),
    context="any",
)

UNUSED_PUBLIC_ENV_KEY = Rule(
    id="UNUSED_PUBLIC_ENV_KEY",
    name="Public (browser-exposed) environment variable never used",
    severity=Severity.MEDIUM,
    category="insecure-defaults",
    message="This public env key ships to the browser but is used nowhere.",
    pattern="",
    why=(
        "NEXT_PUBLIC_/VITE_/REACT_APP_ (and similar) values are inlined into the "
        "client bundle and shipped to every visitor's browser. A public key that "
        "is referenced nowhere in the code is exposed to the world for no reason — "
        "leftover attack surface from an abandoned integration."
    ),
    fix=(
        "Remove the unused public key from the .env file, and rotate the "
        "underlying credential if it was ever real. Never keep a browser-exposed "
        "value you are not using."
    ),
    references=("https://cwe.mitre.org/data/definitions/1188.html",),
    context="any",
)

# --------------------------------------------------------------- CSP domains

_CSP_CONTEXT_RE = re.compile(
    r"(?i)content-security-policy"
    r"|(?:default|script|style|img|connect|font|frame|media|object|worker|child|manifest)-src"
)
# a dotted host, optionally with a scheme in front (https://cdn.x.com, //cdn.x.com, cdn.x.com)
_DOMAIN_RE = re.compile(
    r"(?:https?:)?(?://)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)",
    re.IGNORECASE,
)
# CSP keywords and non-domains that look domain-ish but are not real hosts.
_DOMAIN_SKIP = {
    "self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic",
    "data", "blob", "mediastream", "filesystem", "localhost",
}

DEAD_CSP_DOMAIN = Rule(
    id="DEAD_CSP_DOMAIN",
    name="CSP allow-lists a domain that the code never uses",
    severity=Severity.LOW,
    category="insecure-defaults",
    message="This domain is allowed by the CSP but referenced nowhere in the code.",
    pattern="",
    why=(
        "A domain in the Content-Security-Policy that appears nowhere else in the "
        "repository is dead policy — typically from an integration that was "
        "removed. It needlessly widens what the browser is allowed to load and "
        "signals that nobody is maintaining the policy against real usage."
    ),
    fix=(
        "Remove the unused domain from the CSP. If the domain is only referenced "
        "at runtime (e.g. built from an env var), silence this with a trailing "
        "'# ajar:ignore' on the directive."
    ),
    references=(
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    ),
    context="any",
)


def _is_env_file(name: str) -> bool:
    """A real .env file whose keys we analyze (not a template)."""
    return bool(_ENV_FILE_RE.match(name)) and not _ENV_TEMPLATE_RE.search(name)


def _is_any_env_file(name: str) -> bool:
    """Any .env* file, template included — excluded from the usage corpus so a
    key listed in .env.example does not count as 'used'."""
    return bool(_ENV_FILE_RE.match(name))


def _ignored(line: str) -> bool:
    return "ajar:ignore" in line


def find_unused_env_keys(file_texts: dict[Path, str]) -> list[Finding]:
    env_files = {p: t for p, t in file_texts.items() if _is_env_file(p.name)}
    if not env_files:
        return []
    # Usage corpus: every file that is not a .env* file (templates included, so a
    # key echoed in .env.example does not mask a genuinely unused key). Without a
    # corpus we cannot tell used from unused, so we stay silent.
    corpus = "\n".join(
        t for p, t in file_texts.items() if not _is_any_env_file(p.name)
    )
    if not corpus.strip():
        return []

    findings: list[Finding] = []
    for path, text in env_files.items():
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _ignored(line):
                continue
            m = _ENV_KEY_RE.match(line)
            if not m:
                continue
            key = m.group(1)
            if re.search(r"\b" + re.escape(key) + r"\b", corpus):
                continue  # referenced somewhere — used
            is_public = key.startswith(_PUBLIC_PREFIXES)
            rule = UNUSED_PUBLIC_ENV_KEY if is_public else UNUSED_ENV_KEY
            findings.append(
                Finding(
                    rule=rule,
                    path=str(path),
                    line=lineno,
                    column=line.index(key) + 1,
                    evidence=line.strip()[:200],
                )
            )
    return findings


def find_dead_csp_domains(file_texts: dict[Path, str]) -> list[Finding]:
    csp_hits: list[tuple[Path, int, int, str, str]] = []  # path, line, col, domain, evidence
    usage_parts: list[str] = []
    for path, text in file_texts.items():
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _CSP_CONTEXT_RE.search(line):
                if _ignored(line):
                    continue
                for m in _DOMAIN_RE.finditer(line):
                    dom = m.group(1).lower()
                    if dom in _DOMAIN_SKIP or "." not in dom:
                        continue
                    csp_hits.append((path, lineno, m.start(1) + 1, dom, line.strip()[:200]))
            else:
                usage_parts.append(line)
    if not csp_hits:
        return []

    usage = "\n".join(usage_parts).lower()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path, lineno, col, dom, evidence in csp_hits:
        if dom in usage:  # actually referenced in real code somewhere
            continue
        key = (str(path), dom)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                rule=DEAD_CSP_DOMAIN,
                path=str(path),
                line=lineno,
                column=col,
                evidence=evidence,
            )
        )
    return findings


def find_project_findings(file_texts: dict[Path, str]) -> list[Finding]:
    """Run every cross-file, project-level check over the collected files."""
    findings: list[Finding] = []
    findings.extend(find_unused_env_keys(file_texts))
    findings.extend(find_dead_csp_domains(file_texts))
    return findings
