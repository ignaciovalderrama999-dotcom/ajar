"""Tests for the ajar scanning engine."""

from pathlib import Path

import pytest

from ajar.models import Severity
from ajar.rules import load_rules
from ajar.scanner import scan_path


@pytest.fixture(scope="module")
def rules():
    return load_rules()


def test_rules_load_and_are_valid(rules):
    assert len(rules) > 10
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    # Every rule must teach, not just flag.
    for rule in rules:
        assert rule.why, f"{rule.id} is missing a 'why'"
        assert rule.fix, f"{rule.id} is missing a 'fix'"


def test_detects_fail_open_auth(tmp_path, rules):
    f = tmp_path / "app.py"
    f.write_text('if env != "production":\n    require_auth = False\n')
    findings = scan_path(f, rules)
    ids = {x.rule.id for x in findings}
    assert "FAILOPEN_AUTH_ENV_BYPASS" in ids


def test_detects_hardcoded_aws_key(tmp_path, rules):
    f = tmp_path / "config.py"
    f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_path(f, rules)
    assert any(x.rule.id == "SECRET_AWS_ACCESS_KEY" for x in findings)
    assert any(x.rule.severity is Severity.CRITICAL for x in findings)


def test_detects_debug_and_verify(tmp_path, rules):
    f = tmp_path / "settings.py"
    f.write_text("DEBUG = True\nrequests.get(url, verify=False)\n")
    ids = {x.rule.id for x in scan_path(f, rules)}
    assert "DEFAULT_DEBUG_ON" in ids
    assert "DEFAULT_TLS_VERIFY_FALSE" in ids


def test_inline_ignore_suppresses(tmp_path, rules):
    f = tmp_path / "settings.py"
    f.write_text("DEBUG = True  # ajar:ignore\n")
    assert scan_path(f, rules) == []


def test_inline_ignore_specific_rule(tmp_path, rules):
    f = tmp_path / "settings.py"
    f.write_text("DEBUG = True  # ajar:ignore DEFAULT_DEBUG_ON\n")
    assert scan_path(f, rules) == []


def test_clean_file_has_no_findings(tmp_path, rules):
    f = tmp_path / "clean.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    assert scan_path(f, rules) == []


def test_detects_sql_injection_fstring(tmp_path, rules):
    f = tmp_path / "db.py"
    f.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
    assert any(x.rule.id == "SQLI_FSTRING" for x in scan_path(f, rules))


def test_parameterized_query_is_clean(tmp_path, rules):
    f = tmp_path / "db.py"
    f.write_text('cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n')
    ids = {x.rule.id for x in scan_path(f, rules)}
    assert "SQLI_FSTRING" not in ids
    assert "SQLI_CONCAT" not in ids


def test_detects_command_and_deserialization(tmp_path, rules):
    f = tmp_path / "app.py"
    f.write_text(
        'os.system("ping " + host)\n'
        "subprocess.run(cmd, shell=True)\n"
        "pickle.loads(data)\n"
        "yaml.load(data)\n"
    )
    ids = {x.rule.id for x in scan_path(f, rules)}
    assert {"CMDI_OS_SYSTEM", "CMDI_SHELL_TRUE", "DESERIAL_PICKLE", "DESERIAL_YAML_LOAD"} <= ids


def test_yaml_safe_load_is_clean(tmp_path, rules):
    f = tmp_path / "app.py"
    f.write_text(
        "yaml.safe_load(data)\n"
        "yaml.load(data, Loader=yaml.SafeLoader)\n"
    )
    assert not any(x.rule.id == "DESERIAL_YAML_LOAD" for x in scan_path(f, rules))


def test_eval_not_flagged_in_words(tmp_path, rules):
    f = tmp_path / "app.py"
    f.write_text('msg = "task executed and evaluated"\n')
    assert not any(x.rule.id == "CMDI_EVAL_EXEC" for x in scan_path(f, rules))


def test_detects_dos_missing_timeout(tmp_path, rules):
    f = tmp_path / "net.py"
    f.write_text('requests.get("http://example.com")\n')
    assert any(x.rule.id == "DOS_NO_REQUEST_TIMEOUT" for x in scan_path(f, rules))


def test_request_with_timeout_is_clean(tmp_path, rules):
    f = tmp_path / "net.py"
    f.write_text('requests.get("http://example.com", timeout=5)\n')
    assert not any(x.rule.id == "DOS_NO_REQUEST_TIMEOUT" for x in scan_path(f, rules))


def test_detects_redos_and_decompression_bomb(tmp_path, rules):
    f = tmp_path / "risky.py"
    f.write_text('pat = re.compile("(a+)+")\narchive.extractall("/tmp")\n')
    ids = {x.rule.id for x in scan_path(f, rules)}
    assert "DOS_REDOS_NESTED_QUANTIFIER" in ids
    assert "DOS_DECOMPRESSION_BOMB" in ids


def test_skips_binary_and_vendor_dirs(tmp_path, rules):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text('const DEBUG = True')
    real = tmp_path / "real.py"
    real.write_text("DEBUG = True\n")
    findings = scan_path(tmp_path, rules)
    paths = {Path(x.path).name for x in findings}
    assert "x.js" not in paths
    assert "real.py" in paths
