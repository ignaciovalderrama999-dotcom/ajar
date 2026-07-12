# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.8] - 2026-07-12

### Added
- **Four more languages** with the full structural engine: **Go, Java, PHP and
  C#** — bringing supported languages to **8** (Python, JavaScript, TypeScript,
  TSX, Go, Java, PHP, C#). New injection/deserialization/XXE rules per language.
- **Host security audit** (`ajar host`): read-only, local-only inspection of the
  machine's **own** listening ports, exposed databases/dev servers, and firewall
  state. It never opens a network connection and cannot be pointed at another
  machine. Requires `pip install ajar-scanner[host]` (psutil).
- **CSRF / cross-origin rules**: `CSRF_SAMESITE_NONE` (cookie set with
  `SameSite=None`), `CORS_REFLECTS_ORIGIN` (echoing the request Origin back), and
  `CORS_CREDENTIALS_WILDCARD` (`credentials: true` with a wildcard origin).
- **NoSQL injection rules**: `$where` injection, operator injection from request
  bodies, and raw Mongoose `.where()` expressions.
- **New secret patterns**: Twilio, SendGrid, npm, Discord bot, and Square tokens.

### Changed
- **Taint analysis reaches further.** New sources (request headers/cookies,
  PHP `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`, Java `getParameter`/`getHeader`)
  and new sinks (reflected XSS via `res.send`/`write`/`end`, open redirect via
  `redirect(...)`, and SQL `->query(...)` for PHP/mysqli). Variable boundary
  matching now understands `$`-prefixed PHP variables. Same-origin literals are
  still excluded from SSRF/redirect flows to avoid false positives.

### Legal / safety
- Documentation hardened for **defensive, local-only** use across README,
  DISCLAIMER, SECURITY, and ACCEPTABLE_USE: ajar only reads and reports, never
  modifies system state, and never contacts a remote host. The included skill now
  instructs assistants to **guide** the user on host findings (ports/services/
  firewall) rather than change the system themselves.

### Added (earlier, now shipping in 0.1.8)
- **Entropy-based secret detection** (`SECRET_HIGH_ENTROPY`): catches random,
  high-entropy strings that match no known vendor pattern — an independent
  implementation of the Shannon-entropy technique, tuned to ignore prose, paths,
  and ids to keep false positives low.

### Changed
- `DOS_REDOS_NESTED_QUANTIFIER` is now precise (pattern `[+*]\)[+*]`): it no
  longer mistakes arithmetic like `(a * b) * c` for a catastrophic regex.

### Earlier Unreleased
- **Structural analysis engine (tree-sitter)** for Python, JavaScript,
  TypeScript, and TSX, available via `pip install ajar[full]`. Matches inside
  comments and string literals are ignored (killing the biggest class of false
  positive), while secrets are still detected inside strings. Falls back to
  pattern scanning when the parsers are not installed.
- Per-rule `context` field (`code` | `string` | `any`) controlling where a match
  is allowed to sit.
- 6 JavaScript/TypeScript/Next.js rules: `document.write` XSS, `javascript:`
  URLs, `new Function`, `fetch`/`axios` SSRF, `NEXT_PUBLIC_` secret exposure,
  and open redirects. **44 rules total.**
- `.ajar.yml` project configuration (`min_severity`, `fail_on`, `exclude`,
  `disable`) with auto-discovery; CLI flags override it.
- Baseline mode: `--write-baseline` records accepted findings and `--baseline`
  reports only new ones, so ajar adopts cleanly into existing codebases.
- `--exclude GLOB` to skip paths (repeatable).
- `ajar rules --format md` and a generated [RULES.md](RULES.md) rule catalog.
- pre-commit hook (`.pre-commit-hooks.yaml`) and a Dockerfile.
- Comparison table and FAQ in the README.

## [0.1.0] - 2026-07-02

### Added
- Initial release of **ajar**, a defensive scanner for fail-open logic and
  insecure configuration defaults.
- 38 detection rules across 5 categories:
  - **fail-open** — auth disabled by environment, TLS verify defaults off,
    access granted in error handlers, default-allow policies.
  - **insecure-defaults** — debug mode on, wildcard CORS, bind to 0.0.0.0,
    world-writable permissions, weak hashes, insecure cookies.
  - **injection** — SQL injection, command injection, XSS, SSRF, path traversal,
    unsafe deserialization, template injection, open redirect.
  - **denial-of-service** — missing timeouts, ReDoS, decompression bombs,
    user-controlled regex.
  - **secrets** — hardcoded AWS keys, private keys, tokens, credentials in URLs.
- Terminal, JSON, and SARIF output formats.
- `--fail-on` / `--min-severity` thresholds and non-zero exit codes for CI.
- Inline suppression via `# ajar:ignore` (all rules or a specific id).
- `ajar rules` command to list all loaded rules.
- Transparent, user-editable YAML rules and support for `--rules` custom dirs.
- GitHub Actions workflow and SARIF upload for code scanning.

[Unreleased]: https://github.com/ignaciovalderrama999-dotcom/ajar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ignaciovalderrama999-dotcom/ajar/releases/tag/v0.1.0
