"""Tests for the tree-sitter structural engine and JS/TS/Next.js rules.

These tests require the optional parsers (installed via the `dev` extra). If
tree-sitter is not available, the comment/string suppression is skipped, so the
suppression tests are guarded by `parsers_available()`.
"""

import json

import pytest

from ajar.cli import main
from ajar.parsing import parsers_available
from ajar.rules import load_rules
from ajar.scanner import scan_path

requires_parsers = pytest.mark.skipif(
    not parsers_available(), reason="tree-sitter parsers not installed"
)


@pytest.fixture(scope="module")
def rules():
    return load_rules()


@requires_parsers
def test_python_comment_is_not_flagged(tmp_path, rules):
    f = tmp_path / "a.py"
    f.write_text("# remember: never use verify=False in prod\nx = 1\n")
    assert scan_path(f, rules) == []


@requires_parsers
def test_python_string_is_not_flagged(tmp_path, rules):
    f = tmp_path / "a.py"
    f.write_text('DOC = "passing verify=False disables TLS"\n')
    assert not any(x.rule.id == "DEFAULT_TLS_VERIFY_FALSE" for x in scan_path(f, rules))


@requires_parsers
def test_python_real_code_still_flagged(tmp_path, rules):
    f = tmp_path / "a.py"
    f.write_text("requests.get(url, verify=False)\n")
    assert any(x.rule.id == "DEFAULT_TLS_VERIFY_FALSE" for x in scan_path(f, rules))


@requires_parsers
def test_secret_inside_string_is_still_flagged(tmp_path, rules):
    # Secrets live inside strings on purpose; masking must NOT hide them.
    f = tmp_path / "a.py"
    f.write_text('AWS = "AKIAIOSFODNN7EXAMPLE"\n')
    assert any(x.rule.id == "SECRET_AWS_ACCESS_KEY" for x in scan_path(f, rules))


@requires_parsers
def test_tsx_comment_and_string_not_flagged(tmp_path, rules):
    f = tmp_path / "page.tsx"
    f.write_text('// el.innerHTML = bad\nconst s = "innerHTML = text";\n')
    assert scan_path(f, rules) == []


@requires_parsers
def test_tsx_real_innerhtml_flagged(tmp_path, rules):
    f = tmp_path / "page.tsx"
    f.write_text("el.innerHTML = userInput;\n")
    assert any(x.rule.id == "XSS_INNERHTML" for x in scan_path(f, rules))


def test_nextjs_rules_present(rules):
    ids = {r.id for r in rules}
    assert {
        "XSS_DOCUMENT_WRITE",
        "NEXT_PUBLIC_SECRET",
        "SSRF_FETCH_USER_URL",
        "CODE_EXEC_NEW_FUNCTION",
        "OPEN_REDIRECT_JS",
    } <= ids


def test_next_public_secret_detected(tmp_path, capsys):
    (tmp_path / "config.ts").write_text(
        "const s = process.env.NEXT_PUBLIC_API_SECRET;\n"
    )
    main(["scan", str(tmp_path), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert any(f["rule_id"] == "NEXT_PUBLIC_SECRET" for f in out["findings"])
