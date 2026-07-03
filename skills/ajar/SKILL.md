---
name: ajar
description: "Scans a codebase for real security vulnerabilities — SQL injection, XSS, SSRF, command injection, insecure deserialization, path traversal, fail-open auth logic, insecure defaults (DEBUG, CORS, TLS), denial-of-service (ReDoS, missing timeouts), and hardcoded secrets — across Python, JavaScript, TypeScript, and TSX (React/Next.js). Runs the ajar scanner, explains each finding, and helps the user fix it. Use when the user wants to secure, harden, audit, or security-review their project, web app, API, or AI-generated code, or asks 'is my code safe?'. Defensive only: it analyzes and protects, never attacks."
allowed-tools: Bash Read Edit Grep Glob
---

# ajar — secure your project

ajar is a **defensive** security scanner. This skill runs it on the user's code,
explains every finding in plain language, and helps them close each one. It
analyzes and protects — it never generates exploits and never touches remote
systems.

## When to use

- The user asks to **make their project / web / app secure**, or to do a
  **security review / audit / hardening**.
- Reviewing **AI-generated code** before shipping it.
- Checking for hardcoded secrets, injection (SQL/command/XSS), SSRF, insecure
  configuration, fail-open logic, or denial-of-service risks.

## When NOT to use

- To attack, exploit, scan, or test systems the user does **not** own or is not
  authorized to review. ajar only reads local files; keep it that way.
- As a guarantee of security — it is a strong first line of defense, not a
  certificate. Say so honestly.

## Workflow

### 1. Make sure ajar is available

Run `ajar --version`. If it is not installed, install it from the bundled
package (the repository that contains this skill — the folder two levels up that
holds `pyproject.toml`):

```bash
pip install "ajar[full]"          # if published, or:
pip install "<path-to-repo-root>[full]"   # e.g. the checkout containing pyproject.toml
```

The `[full]` extra adds the tree-sitter engine so comments and strings never
cause false positives in Python/JS/TS/TSX. Without it ajar still runs in
pattern-only mode.

### 2. Scan the code

Run the scanner on the path the user points to (default: the current project),
in JSON so you can reason over the results:

```bash
ajar scan <path> --format json
```

Useful flags: `--min-severity high` to focus, `--exclude <glob>` to skip folders
(e.g. `--exclude node_modules --exclude tests`).

### 3. Present the findings

Summarize by severity (critical → high → medium → low). For each finding show:
- **Where:** `file:line`
- **What:** the rule name and one-line message
- **Why it's dangerous:** the `why` field
- **The fix:** the `fix` field

Group related findings so the user isn't overwhelmed. Lead with the most severe.

### 4. Fix, with the user

Work through findings worst-first. For each, apply the recommended fix using
Read + Edit on the real file. Guidelines:
- Make the **minimal, correct** change (parameterize the query, load the secret
  from env, add the timeout, default auth to on, etc.).
- For anything risky or ambiguous (deleting code, changing auth flow), explain
  the change and confirm with the user before applying.
- **Never** introduce offensive code, backdoors, or ways to disable the check.
- If a finding is a genuine false positive or an accepted risk, silence it
  explicitly with an inline `# ajar:ignore <RULE_ID>` comment or a `disable:`
  entry in `.ajar.yml`, and say why.

### 5. Re-scan to confirm

Run `ajar scan <path>` again and confirm the fixed issues are gone. Repeat the
fix/re-scan loop until the scan is clean at the agreed severity threshold, or
the remaining findings are documented and accepted.

### 6. Be honest about the result

When done, state plainly: ajar closed the **common, detectable** vulnerabilities,
but it cannot find business-logic or design flaws. Recommend a human review for
anything security-critical. A clean scan is reassuring, not a guarantee.

## What ajar detects

- **Injection & code execution:** SQL injection, command injection, `eval`/`exec`/`new Function`, XSS (`innerHTML`, `dangerouslySetInnerHTML`, `document.write`), SSRF, path traversal, unsafe deserialization (`pickle`, `yaml.load`), SSTI, open redirect.
- **Fail-open logic:** auth disabled by a missing/mismatched env var, access granted in error handlers, TLS verification defaulting off, default-allow policies.
- **Insecure defaults:** `DEBUG=True`, wildcard CORS, bind to `0.0.0.0`, world-writable permissions, weak hashes (MD5/SHA1), insecure cookies.
- **Denial of service:** missing request timeouts, catastrophic-backtracking regex (ReDoS), user-controlled regex, decompression bombs.
- **Secrets:** hardcoded AWS keys, private keys, Slack tokens, credentials in URLs, and Next.js secrets leaked to the browser via `NEXT_PUBLIC_`.

Full catalog: run `ajar rules` or see `RULES.md` in the repository.
