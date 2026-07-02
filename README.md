<h1 align="center">ajar 🚪</h1>

<p align="center">
  <b>Find the door you left open by default.</b><br>
  A defensive scanner for <i>fail-open logic</i>, <i>insecure defaults</i>, and <i>web vulnerabilities</i> — that explains every fix.
</p>

<p align="center">
  <img alt="CI" src="https://github.com/your-username/ajar/actions/workflows/ci.yml/badge.svg">
  <img alt="license" src="https://img.shields.io/badge/license-Apache_2.0-green">
  <img alt="python" src="https://img.shields.io/badge/python-3.9%2B-blue">
  <img alt="rules" src="https://img.shields.io/badge/rules-38-informational">
  <img alt="local only" src="https://img.shields.io/badge/telemetry-none-brightgreen">
  <img alt="stance" src="https://img.shields.io/badge/stance-analyze%20%26%20protect-blueviolet">
</p>

<p align="center">
  <img src="assets/demo.svg" alt="ajar scanning a project and explaining each finding" width="760">
</p>

---

Most secret scanners look for the credential you **put in** (`API_KEY = "sk-123"`).

**ajar looks for the door you left open by default** — code that silently runs
*insecure* when a config is missing, an environment name differs, or an error
gets swallowed. No exploit required: the default *is* the vulnerability.

```python
if os.getenv("APP_ENV") != "production":
    require_auth = False        # 🚪 unset/typo'd env → auth is OFF in prod

requests.get(url, verify=False) # 🚪 every request open to a man-in-the-middle

try:
    return check_permission(user)
except Exception:
    return True                 # 🚪 an error becomes a free pass
```

Nobody flags these well. That's the gap ajar fills.

## What it scans

Point ajar at a web app or SaaS backend and it flags five families of risk:

| Category | Examples |
|---|---|
| 🚪 **fail-open** *(flagship)* | auth disabled by a missing env var, `verify=False` defaults, errors that grant access |
| ⚙️ **insecure-defaults** | `DEBUG=True`, wildcard CORS, `0.0.0.0` binds, weak hashes, insecure cookies |
| 💉 **injection** *(web)* | SQL injection, command injection, XSS, SSRF, path traversal, unsafe deserialization, SSTI, open redirect |
| 🌊 **denial-of-service** | missing timeouts, catastrophic-backtracking regex (ReDoS), decompression bombs, user-controlled regex |
| 🔑 **secrets** | hardcoded AWS keys, private keys, tokens, credentials in URLs |

Works on **Python and JS/TS** today. Every rule is defensive — it explains the
attack and the safe fix, and never produces an exploit.

## Why ajar is different

- 🎯 **Fail-open first.** The flagship category is *fail-open logic*, not just secrets — the misconfigurations behind real breaches (open buckets, auth-less admin panels, debug in prod).
- 🎓 **It teaches.** Every finding explains **how an attacker exploits it** and **exactly how to fix it**, with references. You learn while you scan.
- 🔒 **Trust by design.** 100% local. **Zero telemetry.** Your code never leaves your machine. Rules are plain, readable YAML you can audit in `ajar/rules/`.
- ⚡ **Tiny footprint.** One dependency, pip-installable, runs anywhere Python does. Terminal, JSON, and SARIF output for CI.

## Install

```bash
pip install ajar        # once published to PyPI
# or, from source:
git clone https://github.com/your-username/ajar && cd ajar && pip install .
```

## Usage

```bash
ajar scan .                       # scan the current project
ajar scan path/to/file.py         # scan one file
ajar scan examples/vulnerable_webapp.py  # demo: SQLi, XSS, SSRF, RCE, path traversal
ajar scan . --min-severity high   # only show high+ findings
ajar scan . --exclude tests --exclude '*.min.js'  # skip paths (repeatable)
ajar scan . --format json         # machine-readable output
ajar scan . --format sarif        # GitHub code scanning
ajar rules                        # list every rule ajar checks
```

### Example

```console
$ ajar scan examples/vulnerable_config.py

 CRITICAL  examples/vulnerable_config.py:16:5
   Auth disabled outside production  [FAILOPEN_AUTH_ENV_BYPASS]
   Authentication is switched off based on an environment name.
   code: require_auth = False
   why: If the env var that flips this is missing or misspelled in production,
        the app boots wide open with no authentication. The default IS the bug.
   fix: Fail closed — default auth to ON and require an explicit, logged opt-out.
   ref: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

Found 9 open doors: 2 critical · 6 high · 1 medium
```

## Use it in CI

ajar returns a non-zero exit code when it finds an issue at or above
`--fail-on` (default: `medium`), so it drops straight into any pipeline.
A ready-made GitHub Action lives in [`.github/workflows/ajar.yml`](.github/workflows/ajar.yml).

```yaml
- run: pip install ajar
- run: ajar scan . --fail-on high
```

## Suppressing a finding

When something is a deliberate, reviewed exception, silence it inline:

```python
DEBUG = True  # ajar:ignore                    # silence every rule on this line
DEBUG = True  # ajar:ignore DEFAULT_DEBUG_ON    # silence one specific rule
```

## Writing your own rules

Rules are transparent YAML — no hidden logic. Drop a file in `ajar/rules/` (or
point `--rules` at your own directory):

```yaml
rules:
  - id: MY_RULE
    name: Short human name
    severity: high          # info | low | medium | high | critical
    category: fail-open
    message: One-line description of the issue.
    pattern: '(?i)dangerous_setting\s*=\s*True'   # a Python regex
    why: How an attacker abuses this.
    fix: How to close the door.
    references:
      - https://owasp.org/...
```

## Ethics: analyze and protect, never attack 🛡️

ajar is a **defensive** tool, on purpose. It **points at risk and explains the
fix** — it never generates exploits, payloads, or offensive tooling, and it
never connects to or probes any remote system. Its whole job is to help you
close doors before someone else finds them open. That principle is not up for
negotiation, and it guides every rule we add.

## Legal & responsible use ⚖️

- **Use it only on code you own or are authorized to review.** See the full
  [Acceptable Use Policy](ACCEPTABLE_USE.md).
- **It is an aid, not a guarantee.** A clean scan does not mean your app is
  secure. See the [Disclaimer & Limitation of Liability](DISCLAIMER.md).
- **Provided "AS IS", no warranty, no liability** — standard [Apache 2.0](LICENSE)
  terms. You are responsible for how you use it.
- **Found a bug in ajar itself?** See [SECURITY.md](SECURITY.md).
- **Forks & modified copies are the modifier's responsibility, not the
  author's.** Only the official repository is endorsed; the name "ajar" may not
  be used to promote modified versions. Details in the [DISCLAIMER](DISCLAIMER.md).

By using ajar you accept the [DISCLAIMER](DISCLAIMER.md) and
[Acceptable Use Policy](ACCEPTABLE_USE.md). If you do not agree, do not use it.

## Roadmap

- [ ] AST-based checks for Python to cut false positives further (injection rules are heuristic today)
- [ ] More languages (Go, Java, PHP, Ruby)
- [ ] `--baseline` to accept existing findings and only flag new ones
- [ ] Publish to PyPI
- [ ] Pre-commit hook

## Contributing

New rules are the best contribution — especially fail-open patterns you've seen
in the wild. Keep every rule **defensive, explainable, and referenced**. PRs and
issues welcome.

## License

Apache License 2.0 © 2026 Ignacio Valderrama. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
