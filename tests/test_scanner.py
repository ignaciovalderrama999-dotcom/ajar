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


def test_entropy_flags_random_secret(tmp_path, rules):
    # A random secret assigned to a NON-secret-looking variable: no vendor
    # pattern and no secret keyword catch it, so only entropy can.
    f = tmp_path / "cfg.py"
    f.write_text('config_value = "aG9x8Qz2Kp7Lm4Rt9Wv3Bn6Xy1Zc5Df8"\n')
    assert any(x.rule.id == "SECRET_HIGH_ENTROPY" for x in scan_path(f, rules))


def test_entropy_ignores_prose_and_paths(tmp_path, rules):
    f = tmp_path / "cfg.py"
    f.write_text(
        'msg = "hola como estas todo bien por aca amigo"\n'
        'path = "src/components/Hero/HeroScene/index"\n'
    )
    assert not any(x.rule.id == "SECRET_HIGH_ENTROPY" for x in scan_path(f, rules))


def test_entropy_ignores_mixed_case_asset_path(tmp_path, rules):
    # Found auditing a real project: a file path mixing case/digits (an asset
    # name, not a secret) was flagged by the entropy heuristic.
    f = tmp_path / "sw.js"
    f.write_text("const url = '/components/cart_DASHBOARD_V10.html';\n")
    assert not any(x.rule.id == "SECRET_HIGH_ENTROPY" for x in scan_path(f, rules))


def test_entropy_still_flags_secret_with_slash(tmp_path, rules):
    # A base64-ish secret can legitimately contain a slash; must not be
    # swallowed by the new path exclusion (no recognizable extension at the end).
    f = tmp_path / "cfg.py"
    f.write_text('key = "aG9x8Qz2Kp7Lm4Rt9Wv3Bn6Xy1Zc5Df8/"\n')
    assert any(x.rule.id == "SECRET_HIGH_ENTROPY" for x in scan_path(f, rules))


def test_taint_flags_cross_line_flow(tmp_path, rules):
    # User input stored in a variable and used in a sink several lines later —
    # pattern rules can't see it, taint analysis must.
    f = tmp_path / "app.py"
    f.write_text(
        "def h():\n"
        "    uid = request.args.get('id')\n"
        "    q = build(uid)\n"
        "    cursor.execute(q)\n"
    )
    assert any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(f, rules))


def test_taint_ignores_same_origin_fetch(tmp_path, rules):
    # Found auditing a real Next.js app: a relative-path fetch with dynamic
    # query params is same-origin, not SSRF. new URLSearchParams() is a generic
    # builder, not a taint source either.
    f = tmp_path / "Feed.tsx"
    f.write_text(
        "const params = new URLSearchParams();\n"
        'const res = await fetch(`/api/account/activity?${params.toString()}`);\n'
    )
    assert scan_path(f, rules) == []


def test_taint_flags_real_ssrf_and_real_search_params(tmp_path, rules):
    f1 = tmp_path / "a.ts"
    f1.write_text(
        "export async function GET(req) {\n"
        '  const target = req.nextUrl.searchParams.get("url");\n'
        "  const res = await fetch(target);\n"
        "}\n"
    )
    assert any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(f1, rules))

    f2 = tmp_path / "b.ts"
    f2.write_text(
        "export async function GET(req) {\n"
        '  const id = req.nextUrl.searchParams.get("id");\n'
        "  cursor.execute(id);\n"
        "}\n"
    )
    assert any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(f2, rules))


def test_taint_respects_sanitizer(tmp_path, rules):
    # Input validated with int() before the sink must NOT be flagged.
    f = tmp_path / "app.py"
    f.write_text(
        "def h():\n"
        "    uid = int(request.args.get('id'))\n"
        "    cursor.execute(uid)\n"
    )
    assert not any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(f, rules))


def test_taint_quiet_on_safe_flow(tmp_path, rules):
    f = tmp_path / "app.py"
    f.write_text(
        "def h():\n"
        "    x = get_config('id')\n"
        "    q = 'SELECT 1'\n"
        "    cursor.execute(q)\n"
    )
    assert not any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(f, rules))


def test_redos_does_not_flag_math(tmp_path, rules):
    # Arithmetic like (a * b) * c must NOT be mistaken for a catastrophic regex.
    f = tmp_path / "anim.js"
    f.write_text(
        "camera.position.x += (ptr.x * 0.3 - camera.position.x) * 0.04;\n"
        "const v = (t * 0.04) % 1;\n"
    )
    assert not any(x.rule.id == "DOS_REDOS_NESTED_QUANTIFIER" for x in scan_path(f, rules))


def test_skips_binary_and_vendor_dirs(tmp_path, rules):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text('const DEBUG = True')
    real = tmp_path / "real.py"
    real.write_text("DEBUG = True\n")
    findings = scan_path(tmp_path, rules)
    paths = {Path(x.path).name for x in findings}
    assert "x.js" not in paths
    assert "real.py" in paths


def test_csharp_detects_injection(tmp_path, rules):
    f = tmp_path / "X.cs"
    f.write_text(
        "class X {\n"
        "  void F(string id) {\n"
        "    // new SqlCommand(\"...\" + id) in a comment must NOT flag\n"
        "    var cmd = new SqlCommand(\"SELECT * FROM u WHERE id=\" + id);\n"
        "    var bf = new BinaryFormatter();\n"
        "  }\n"
        "}\n"
    )
    ids = {x.rule.id for x in scan_path(f, rules)}
    assert "SQLI_CSHARP" in ids
    assert "DESERIAL_CSHARP_BINARYFORMATTER" in ids


def test_csharp_parameterized_is_clean(tmp_path, rules):
    f = tmp_path / "X.cs"
    f.write_text(
        "class X {\n"
        "  void F(string id) {\n"
        "    var cmd = new SqlCommand(\"SELECT * FROM u WHERE id=@id\");\n"
        "    cmd.Parameters.AddWithValue(\"@id\", id);\n"
        "  }\n"
        "}\n"
    )
    assert not any(x.rule.id == "SQLI_CSHARP" for x in scan_path(f, rules))


def test_samesite_none_flagged_lax_clean(tmp_path, rules):
    bad = tmp_path / "bad.js"
    bad.write_text('res.cookie("sid", v, { sameSite: "none", secure: true });\n')
    assert any(x.rule.id == "CSRF_SAMESITE_NONE" for x in scan_path(bad, rules))
    good = tmp_path / "good.js"
    good.write_text('res.cookie("sid", v, { sameSite: "lax" });\n')
    assert not any(x.rule.id == "CSRF_SAMESITE_NONE" for x in scan_path(good, rules))


def test_cors_reflects_origin_flagged_static_clean(tmp_path, rules):
    bad = tmp_path / "bad.js"
    bad.write_text('res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n')
    assert any(x.rule.id == "CORS_REFLECTS_ORIGIN" for x in scan_path(bad, rules))
    good = tmp_path / "good.js"
    good.write_text('res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");\n')
    assert not any(x.rule.id == "CORS_REFLECTS_ORIGIN" for x in scan_path(good, rules))


def test_cors_credentials_wildcard_flagged(tmp_path, rules):
    bad = tmp_path / "bad.js"
    bad.write_text('app.use(cors({ origin: "*", credentials: true }));\n')
    assert any(x.rule.id == "CORS_CREDENTIALS_WILDCARD" for x in scan_path(bad, rules))
    good = tmp_path / "good.js"
    good.write_text('app.use(cors({ origin: "https://app.example.com", credentials: true }));\n')
    assert not any(x.rule.id == "CORS_CREDENTIALS_WILDCARD" for x in scan_path(good, rules))


def test_taint_reflected_xss_and_open_redirect(tmp_path, rules):
    xss = tmp_path / "xss.js"
    xss.write_text(
        'app.get("/", (req, res) => {\n'
        "  const n = req.query.name;\n"
        "  res.send(n);\n"
        "});\n"
    )
    assert any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(xss, rules))

    red = tmp_path / "red.js"
    red.write_text(
        'app.get("/r", (req, res) => {\n'
        "  const u = req.query.url;\n"
        "  res.redirect(u);\n"
        "});\n"
    )
    assert any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(red, rules))


def test_taint_redirect_to_fixed_path_is_clean(tmp_path, rules):
    f = tmp_path / "red.js"
    f.write_text(
        'app.get("/r", (req, res) => {\n'
        "  const u = req.query.url;\n"
        '  res.redirect("/home");\n'
        "});\n"
    )
    assert not any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(f, rules))


def test_error_disclosure_flagged_and_safe_clean(tmp_path, rules):
    bad = tmp_path / "route.ts"
    bad.write_text("return res.status(500).json({ error: String(err) });\n")
    assert any(x.rule.id == "ERROR_DISCLOSURE" for x in scan_path(bad, rules))
    bad2 = tmp_path / "r2.ts"
    bad2.write_text("res.send({ detail: err.message });\n")
    assert any(x.rule.id == "ERROR_DISCLOSURE" for x in scan_path(bad2, rules))
    good = tmp_path / "ok.ts"
    good.write_text('res.status(400).json({ error: "Invalid input" });\n')
    assert not any(x.rule.id == "ERROR_DISCLOSURE" for x in scan_path(good, rules))


def test_email_html_injection_flagged_and_static_clean(tmp_path, rules):
    bad = tmp_path / "contact.ts"
    bad.write_text("await resend.emails.send({ html: `<p>${name}</p>` });\n")
    assert any(x.rule.id == "HTMLI_EMAIL_TEMPLATE" for x in scan_path(bad, rules))
    good = tmp_path / "ok.ts"
    good.write_text('send({ html: "<p>hello</p>" });\n')
    assert not any(x.rule.id == "HTMLI_EMAIL_TEMPLATE" for x in scan_path(good, rules))


def test_dangerous_html_ignores_static_flags_dynamic(tmp_path, rules):
    # Static, developer-written literal: NOT a false positive anymore.
    static = tmp_path / "Static.tsx"
    static.write_text(
        "<script dangerouslySetInnerHTML={{\n"
        "  __html: `console.log('hi'); document.title = 'X';`\n"
        "}} />\n"
    )
    assert not any(x.rule.id == "XSS_DANGEROUS_HTML" for x in scan_path(static, rules))

    # JSON.stringify of a purely literal object/array: also safe, not flagged.
    jsonlit = tmp_path / "Json.tsx"
    jsonlit.write_text(
        "<script dangerouslySetInnerHTML={{\n"
        "  __html: JSON.stringify({ name: 'Juan', url: 'https://ex.com' })\n"
        "}} />\n"
    )
    assert not any(x.rule.id == "XSS_DANGEROUS_HTML" for x in scan_path(jsonlit, rules))

    # Dynamic value (variable / interpolation / concat / stringify of req.body):
    # still flagged.
    for code in (
        "<div dangerouslySetInnerHTML={{ __html: userHtml }} />\n",
        "<div dangerouslySetInnerHTML={{ __html: `<p>${x}</p>` }} />\n",
        '<div dangerouslySetInnerHTML={{ __html: "<b>" + x }} />\n',
        "<script dangerouslySetInnerHTML={{ __html: `d = ${JSON.stringify(req.body)}` }} />\n",
    ):
        f = tmp_path / "Dyn.tsx"
        f.write_text(code)
        assert any(
            x.rule.id == "XSS_DANGEROUS_HTML" for x in scan_path(f, rules)
        ), code


def test_innerhtml_ignores_static_flags_dynamic(tmp_path, rules):
    static = tmp_path / "s.js"
    static.write_text('el.innerHTML = "Loading ...";\nx.innerHTML = "";\n')
    assert not any(x.rule.id == "XSS_INNERHTML" for x in scan_path(static, rules))
    for code in ("el.innerHTML = message;\n", 'el.innerHTML = "<b>" + x;\n'):
        f = tmp_path / "d.js"
        f.write_text(code)
        assert any(x.rule.id == "XSS_INNERHTML" for x in scan_path(f, rules)), code


def test_entropy_ignores_charset_constant(tmp_path, rules):
    # A charset/alphabet string has maximal entropy but is not a secret.
    f = tmp_path / "gen.ts"
    f.write_text(
        "const possible = "
        "'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';\n"
    )
    assert not any(x.rule.id == "SECRET_HIGH_ENTROPY" for x in scan_path(f, rules))


def test_failopen_ignores_ui_flag(tmp_path, rules):
    # A UI state flag that merely contains "auth" must not read as auth-disable.
    f = tmp_path / "login.ts"
    f.write_text("this.oauthUnavailable = false;\nauthModalOpen = false;\n")
    assert not any(x.rule.id == "FAILOPEN_AUTH_ENV_BYPASS" for x in scan_path(f, rules))


def test_test_files_suppress_heuristic_secrets_keep_vendor(tmp_path, rules):
    # Fake creds in a test dir: generic + entropy suppressed, real AWS key kept.
    (tmp_path / "test").mkdir()
    t = tmp_path / "test" / "login.spec.ts"
    t.write_text(
        'const password = "hunter2demo";\n'
        'const blob = "aG9x8Qz2Kp7Lm4Rt9Wv3Bn6Xy1Zc5Df8";\n'
        'const aws = "AKIAIOSFODNN7EXAMPLE";\n'
    )
    ids = {x.rule.id for x in scan_path(tmp_path, rules)}
    assert "SECRET_GENERIC_ASSIGNMENT" not in ids
    assert "SECRET_HIGH_ENTROPY" not in ids
    assert "SECRET_AWS_ACCESS_KEY" in ids  # real vendor key still caught

    # Same content in NON-test code: heuristic detectors DO fire.
    src = tmp_path / "app.ts"
    src.write_text('const blob = "aG9x8Qz2Kp7Lm4Rt9Wv3Bn6Xy1Zc5Df8";\n')
    assert any(x.rule.id == "SECRET_HIGH_ENTROPY" for x in scan_path(src, rules))


def test_i18n_dir_excluded(tmp_path, rules):
    (tmp_path / "i18n").mkdir()
    (tmp_path / "i18n" / "en.json").write_text('{"msg": "AKIAIOSFODNN7EXAMPLE looking text"}\n')
    real = tmp_path / "real.py"
    real.write_text("DEBUG = True\n")
    paths = {Path(x.path).name for x in scan_path(tmp_path, rules)}
    assert "en.json" not in paths
    assert "real.py" in paths


def test_out_dir_excluded_by_default(tmp_path, rules):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "app.js").write_text("const q = `SELECT * FROM u WHERE id=${id}`;\n")
    real = tmp_path / "real.ts"
    real.write_text("DEBUG = True\n")
    paths = {Path(x.path).name for x in scan_path(tmp_path, rules)}
    assert "app.js" not in paths  # build output skipped


def test_minified_file_skipped(tmp_path, rules):
    # A minified bundle: one enormous line. Pattern rules must not fire on it.
    mini = tmp_path / "vendor.js"
    mini.write_text("var a=1;" + 'x="' + "SELECT * FROM u WHERE id=" + '"+b;' * 400 + "\n")
    assert scan_path(mini, rules) == []
    named = tmp_path / "app.min.js"
    named.write_text('eval("' + "a" * 10 + '");\n')
    assert scan_path(named, rules) == []


def test_taint_header_and_cookie_sources(tmp_path, rules):
    py = tmp_path / "h.py"
    py.write_text(
        "def h():\n"
        '    ua = request.headers.get("X")\n'
        "    cursor.execute(ua)\n"
    )
    assert any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(py, rules))

    php = tmp_path / "h.php"
    php.write_text(
        "<?php\n"
        '$u = $_COOKIE["id"];\n'
        "$out = build($u);\n"
        "$db->query($out);\n"
    )
    assert any(x.rule.id == "TAINT_USER_INPUT_TO_SINK" for x in scan_path(php, rules))
