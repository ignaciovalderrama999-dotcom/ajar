# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/your-username/ajar/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-username/ajar/releases/tag/v0.1.0
