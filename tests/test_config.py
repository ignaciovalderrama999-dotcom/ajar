"""Tests for config-file handling and baseline diffing via the CLI."""

import json

from ajar.cli import main
from ajar.config import find_config, load_config


def test_load_config(tmp_path):
    cfg = tmp_path / ".ajar.yml"
    cfg.write_text(
        "min_severity: high\nfail_on: critical\nexclude:\n  - tests\ndisable:\n  - FOO_BAR\n"
    )
    loaded = load_config(cfg)
    assert loaded.min_severity == "high"
    assert loaded.fail_on == "critical"
    assert loaded.exclude == ("tests",)
    assert "FOO_BAR" in loaded.disable


def test_find_config_discovers_file(tmp_path):
    (tmp_path / ".ajar.yml").write_text("min_severity: low\n")
    assert find_config(tmp_path) is not None
    assert find_config(tmp_path).name == ".ajar.yml"


def test_config_min_severity_and_disable(tmp_path, capsys):
    (tmp_path / ".ajar.yml").write_text(
        "min_severity: high\ndisable:\n  - DEFAULT_BIND_ALL_INTERFACES\n"
    )
    (tmp_path / "app.py").write_text('DEBUG = True\nHOST = "0.0.0.0"\n')
    code = main(["scan", str(tmp_path), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    ids = {f["rule_id"] for f in out["findings"]}
    assert "DEFAULT_DEBUG_ON" in ids            # high, shown
    assert "DEFAULT_BIND_ALL_INTERFACES" not in ids  # disabled
    assert code in (0, 1)


def test_no_config_flag_ignores_file(tmp_path, capsys):
    (tmp_path / ".ajar.yml").write_text("min_severity: critical\n")
    (tmp_path / "app.py").write_text("DEBUG = True\n")
    main(["scan", str(tmp_path), "--no-config", "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert any(f["rule_id"] == "DEFAULT_DEBUG_ON" for f in out["findings"])


def test_baseline_hides_known_findings(tmp_path, capsys):
    app = tmp_path / "app.py"
    app.write_text("DEBUG = True\n")
    baseline = tmp_path / "bl.json"

    main(["scan", str(tmp_path), "--baseline", str(baseline), "--write-baseline"])
    capsys.readouterr()
    assert baseline.is_file()
    assert json.loads(baseline.read_text())["fingerprints"]

    main(["scan", str(tmp_path), "--baseline", str(baseline), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["total"] == 0  # the known finding is suppressed


def test_baseline_shows_new_findings(tmp_path, capsys):
    app = tmp_path / "app.py"
    app.write_text("DEBUG = True\n")
    baseline = tmp_path / "bl.json"
    main(["scan", str(tmp_path), "--baseline", str(baseline), "--write-baseline"])
    capsys.readouterr()

    app.write_text("DEBUG = True\nrequests.get(url, verify=False)\n")
    main(["scan", str(tmp_path), "--baseline", str(baseline), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    ids = {f["rule_id"] for f in out["findings"]}
    assert "DEFAULT_TLS_VERIFY_FALSE" in ids
    assert "DEFAULT_DEBUG_ON" not in ids  # was in baseline
