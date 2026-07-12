"""Tests for NoSQL injection rules and the Go/Java/PHP language additions."""

import pytest

from ajar.rules import load_rules
from ajar.scanner import scan_path

_rules = load_rules()


# ------------------------------------------------------------------- NoSQL
def test_nosql_where_injection(tmp_path):
    f = tmp_path / "a.js"
    f.write_text('db.users.find({ $where: "this.password == \'" + pw + "\'" });\n')
    assert any(x.rule.id == "NOSQL_WHERE_INJECTION" for x in scan_path(f, _rules))


def test_nosql_operator_injection(tmp_path):
    f = tmp_path / "a.js"
    f.write_text("User.find(req.body);\n")
    assert any(x.rule.id == "NOSQL_OPERATOR_INJECTION" for x in scan_path(f, _rules))


def test_nosql_mongoose_raw_where(tmp_path):
    f = tmp_path / "a.js"
    f.write_text("Product.where(`price > ${userInput}`);\n")
    assert any(x.rule.id == "NOSQL_MONGOOSE_RAW_WHERE" for x in scan_path(f, _rules))


def test_nosql_safe_patterns_are_quiet(tmp_path):
    f = tmp_path / "a.js"
    f.write_text(
        "User.find({ email: String(req.body.email) });\n"
        'db.users.find({ status: "active" });\n'
        'Product.where("price").gt(100);\n'
    )
    ids = {x.rule.id for x in scan_path(f, _rules)}
    assert not (ids & {"NOSQL_WHERE_INJECTION", "NOSQL_OPERATOR_INJECTION", "NOSQL_MONGOOSE_RAW_WHERE"})


# --------------------------------------------------------------------- Go
def test_go_sqli_and_cmdi_detected(tmp_path):
    f = tmp_path / "a.go"
    f.write_text(
        'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id=%s", id))\n'
        'exec.Command("sh", "-c", cmd)\n'
    )
    ids = {x.rule.id for x in scan_path(f, _rules)}
    assert "SQLI_GO_SPRINTF" in ids
    assert "CMDI_GO_SHELL" in ids


def test_go_safe_patterns_are_quiet(tmp_path):
    f = tmp_path / "a.go"
    f.write_text(
        'db.Query("SELECT * FROM users WHERE id=$1", id)\n'
        'exec.Command("ping", "-c", "1", host)\n'
    )
    ids = {x.rule.id for x in scan_path(f, _rules)}
    assert not (ids & {"SQLI_GO_SPRINTF", "CMDI_GO_SHELL"})


def test_go_comment_is_not_flagged(tmp_path):
    f = tmp_path / "a.go"
    f.write_text('// db.Query(fmt.Sprintf("...", id))\nfunc f() {}\n')
    assert scan_path(f, _rules) == []


# ------------------------------------------------------------------- Java
def test_java_sqli_and_cmdi_detected(tmp_path):
    f = tmp_path / "Test.java"
    f.write_text(
        'stmt.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
        'Runtime.getRuntime().exec("ping " + host);\n'
    )
    ids = {x.rule.id for x in scan_path(f, _rules)}
    assert "SQLI_JAVA_STATEMENT" in ids
    assert "CMDI_JAVA_RUNTIME_EXEC" in ids


def test_java_safe_patterns_are_quiet(tmp_path):
    f = tmp_path / "Safe.java"
    f.write_text(
        'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id=?");\n'
        'Runtime.getRuntime().exec(new String[]{"ping", host});\n'
    )
    ids = {x.rule.id for x in scan_path(f, _rules)}
    assert not (ids & {"SQLI_JAVA_STATEMENT", "CMDI_JAVA_RUNTIME_EXEC"})


def test_java_comment_is_not_flagged(tmp_path):
    f = tmp_path / "Test.java"
    f.write_text('// stmt.executeQuery("SELECT..." + id);\nclass Test {}\n')
    assert scan_path(f, _rules) == []


# --------------------------------------------------------------------- PHP
def test_php_sqli_cmdi_lfi_detected(tmp_path):
    f = tmp_path / "a.php"
    f.write_text(
        "<?php\n"
        '$conn->query("SELECT * FROM users WHERE id=" . $_GET[\'id\']);\n'
        'system("ping " . $_GET[\'host\']);\n'
        'include($_GET[\'page\'] . ".php");\n'
    )
    ids = {x.rule.id for x in scan_path(f, _rules)}
    assert "SQLI_PHP_CONCAT" in ids
    assert "CMDI_PHP_SHELL" in ids
    assert "LFI_PHP_INCLUDE" in ids


def test_php_safe_patterns_are_quiet(tmp_path):
    f = tmp_path / "safe.php"
    f.write_text(
        "<?php\n"
        '$stmt = $conn->prepare("SELECT * FROM users WHERE id=?");\n'
        '$stmt->bind_param("i", $id);\n'
        'system("ping " . escapeshellarg($host));\n'
        'include("pages/" . $allowedPage . ".php");\n'
    )
    ids = {x.rule.id for x in scan_path(f, _rules)}
    assert not (ids & {"SQLI_PHP_CONCAT", "CMDI_PHP_SHELL", "LFI_PHP_INCLUDE"})


def test_php_comment_is_not_flagged(tmp_path):
    f = tmp_path / "a.php"
    f.write_text('<?php\n// $conn->query("SELECT..." . $_GET[\'id\']);\n')
    assert scan_path(f, _rules) == []


# ---------------------------------------------------------- new secrets
# The example tokens are assembled from pieces at runtime so this test file
# itself contains no contiguous secret — that keeps GitHub's push protection /
# secret scanning from flagging the tests. The temp file the scanner actually
# reads still receives the full, joined value, so detection is tested for real.
@pytest.mark.parametrize(
    ("secret", "rule_id"),
    [
        ("AC" + "1234567890abcdef1234567890abcdef", "SECRET_TWILIO_KEY"),
        ("SG." + "abcdefghijklmnop" + "." + "qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR",
         "SECRET_SENDGRID_KEY"),
        ("npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "SECRET_NPM_TOKEN"),
        ("sq0atp-" + "AbCdEfGhIjKlMnOpQrStUv", "SECRET_SQUARE_TOKEN"),
    ],
)
def test_new_secret_patterns_detected(tmp_path, secret, rule_id):
    f = tmp_path / "a.js"
    f.write_text(f'const tok = "{secret}";\n')
    assert any(x.rule.id == rule_id for x in scan_path(f, _rules))
