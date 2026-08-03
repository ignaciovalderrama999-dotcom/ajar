"""Tests for the cross-file, project-level analysis (ajar.project)."""

from pathlib import Path

import pytest

from ajar.rules import load_rules
from ajar.scanner import scan_path


@pytest.fixture(scope="module")
def rules():
    return load_rules()


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_unused_env_keys_flagged_used_clean(tmp_path, rules):
    _write(
        tmp_path,
        {
            ".env.local": "NEXT_PUBLIC_OLD_API=abc\nDATABASE_URL=x\nUNUSED_THING=1\n",
            "app.ts": "const db = process.env.DATABASE_URL;\n",
        },
    )
    findings = scan_path(tmp_path, rules)
    ids = {f.rule.id for f in findings}
    assert "UNUSED_PUBLIC_ENV_KEY" in ids  # NEXT_PUBLIC_OLD_API ships to browser
    assert "UNUSED_ENV_KEY" in ids  # UNUSED_THING
    # A used key is never flagged.
    assert not any(
        "DATABASE_URL" in f.evidence for f in findings if f.rule.id.startswith("UNUSED")
    )


def test_env_template_and_ignore_are_respected(tmp_path, rules):
    _write(
        tmp_path,
        {
            ".env.example": "FOO=placeholder\n",  # template: not analyzed
            ".env": "DYNAMIC=1  # ajar:ignore\n",  # explicitly silenced
            "main.py": "print('hi')\n",
        },
    )
    ids = {f.rule.id for f in scan_path(tmp_path, rules)}
    assert "UNUSED_ENV_KEY" not in ids


def test_env_example_does_not_mask_unused_key(tmp_path, rules):
    # A key echoed in .env.example must NOT count as "used".
    _write(
        tmp_path,
        {
            ".env": "GHOST_KEY=real\n",
            ".env.example": "GHOST_KEY=\n",
            "main.py": "print('hi')\n",
        },
    )
    ids = {f.rule.id for f in scan_path(tmp_path, rules)}
    assert "UNUSED_ENV_KEY" in ids


def test_single_env_file_alone_no_false_positives(tmp_path, rules):
    # Scanning just an .env file (no code corpus) must not flag everything.
    f = tmp_path / ".env"
    f.write_text("SOLO=1\n")
    assert scan_path(f, rules) == []


def test_dead_csp_domain_flagged_used_clean(tmp_path, rules):
    _write(
        tmp_path,
        {
            "next.config.js": (
                'const csp = "script-src \'self\' '
                'https://dead.emailjs.com https://live.cdn.com";\n'
            ),
            "app.ts": 'fetch("https://live.cdn.com/x");\n',
        },
    )
    findings = [f for f in scan_path(tmp_path, rules) if f.rule.id == "DEAD_CSP_DOMAIN"]
    assert len(findings) == 1  # only the dead domain, not the live one
    assert "emailjs" in findings[0].evidence


def test_csp_all_domains_used_is_clean(tmp_path, rules):
    _write(
        tmp_path,
        {
            "config.js": 'const csp = "script-src \'self\' https://cdn.live.com";\n',
            "index.html": '<script src="https://cdn.live.com/a.js"></script>\n',
        },
    )
    assert not any(f.rule.id == "DEAD_CSP_DOMAIN" for f in scan_path(tmp_path, rules))
