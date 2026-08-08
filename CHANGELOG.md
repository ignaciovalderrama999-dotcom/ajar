# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-08

### Fixed — precision on real projects (from a live audit of a real app)
On a real project the scanner was drowning in noise (39 findings, ~1 real). Root
causes fixed:

- **Lock files are excluded by default** — `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `Gemfile.lock`, `go.sum`, and
  friends. Their public integrity hashes were the single biggest noise source
  (~77% of findings on the audited project).
- **Subresource-Integrity / lockfile checksums are whitelisted** — a value like
  `sha512-…` is a public content hash, never a secret, even outside a lock file
  (import maps, `<script integrity>`).
- **Firebase web `apiKey` is treated as public** — an `AIza…` key in a file with
  `firebaseConfig` / `initializeApp` / `authDomain` is downgraded to medium and
  labeled, because Firebase web keys are public identifiers by design (not the
  same as a secret server key).
- **Duplicate secret hits on one line are de-duplicated** — when a specific
  vendor rule and the generic assignment rule match the same `apiKey:` line, only
  the specific one is reported.
- **`innerHTML` into a text-only element is not XSS** — assignment to a
  `textarea` / `title` / `script` / `style` element (including a variable built
  via `createElement('textarea')`) no longer flags, since that content parses as
  text, not markup (the standard entity-decode idiom).
- **The project's own ignore lists are honored** — `.gitignore` and
  `.vercelignore` exclude files the project itself excludes/does not deploy.
  Patterns that would hide `.env` are dropped, so the env-key analysis still runs.

## [0.2.2] - 2026-08-03

### Fixed — precision (validated on OWASP Juice Shop)
Benchmarked against the OWASP Juice Shop source (locally, read-only): total
findings dropped from **373 to 155** while every real vulnerability was kept
(NoSQL injection, insecure deserialization, SQLi, taint flows). The cut was pure
noise:

- **Heuristic secret detectors are suppressed in test/fixture files.** Generic
  `password = "…"` assignments and entropy no longer fire in `test/`, `spec/`,
  `e2e/`, `cypress/`, `fixtures/`, `__mocks__/`, `*.test.*`, `*.spec.*` — where
  fake credentials are the norm. Specific vendor-key patterns (AWS/Stripe/…) are
  **kept**, since a real key is a leak even in a test.
- **`XSS_INNERHTML` now flags only dynamic content**, mirroring the
  `dangerouslySetInnerHTML` fix: `el.innerHTML = "Loading…"` (a static literal)
  is no longer a false positive; `el.innerHTML = userInput` still is.
- **Entropy ignores alphabet/charset constants** — a string like
  `"ABC…XYZabc…xyz012…9"` has maximal entropy but is obviously not a secret
  (detected via a long ascending character run).
- **`FAILOPEN_AUTH_ENV_BYPASS` no longer matches UI state flags** — a variable
  that merely contains "auth" (e.g. `oauthUnavailable = false`) is not an
  authentication switch. The rule now matches meaningful auth-enforcement names.
- **Localization data is skipped**: `i18n`, `locales`, `locale`, `translations`,
  `lang` directories are strings for humans, a big entropy false-positive source
  and never where bugs live.

## [0.2.1] - 2026-08-03

### Changed
- **Honest wording for the project-level findings.** `UNUSED_ENV_KEY`,
  `UNUSED_PUBLIC_ENV_KEY`, and `DEAD_CSP_DOMAIN` now report *"No static reference
  was found in the scanned project"* rather than claiming the config is
  definitely unused. Static analysis cannot prove absence of use — the value may
  be accessed dynamically (`process.env[name]`), built at runtime
  (`${SUBDOMAIN}.example.com`), loaded from a database, used only in CI/CD,
  defined for another package of a monorepo, or referenced in a skipped file.
  Each finding now lists these caveats and frames itself as a lead to verify, not
  a verdict.

## [0.2.0] - 2026-08-03

### Added — project-aware, cross-file analysis
ajar no longer looks only at one line (or one file) at a time. A new
project-level pass holds the whole repository in view and cross-references
declared configuration against real usage — the mechanical half of a cross-file
audit that a line-by-line scanner (and a busy reviewer) miss, with no LLM in the
loop:

- **`UNUSED_ENV_KEY` / `UNUSED_PUBLIC_ENV_KEY`** — every key in `.env` /
  `.env.local` (templates excluded) is grepped against the whole codebase; keys
  referenced nowhere are flagged. Browser-exposed prefixes (`NEXT_PUBLIC_`,
  `VITE_`, `REACT_APP_`, …) are raised to medium because a stale one ships to
  every visitor. A key echoed only in `.env.example` does not count as used.
- **`DEAD_CSP_DOMAIN`** — every domain allow-listed in a `Content-Security-Policy`
  is grepped against the repo; a domain used nowhere in real code is flagged as
  dead policy (leftover from a removed integration). `# ajar:ignore` on the
  directive silences runtime-only domains.

### Changed
- Web asset files are now scanned: `.html`, `.htm`, `.vue`, `.svelte`, `.astro`,
  `.css`, `.scss`, `.sass`, `.less`. This is where CSP domains and other real
  usage live (so the cross-file check is accurate) and where vulns can hide.
- `.env.local` / `.env.production` (not just a bare `.env`) are now discovered.

## [0.1.10] - 2026-08-03

### Fixed
- **`XSS_DANGEROUS_HTML` no longer fires on static `dangerouslySetInnerHTML`.**
  The old rule flagged the mere presence of `dangerouslySetInnerHTML`. It now
  inspects the `__html` value and only flags a **dynamic** one — a variable,
  a template interpolation (`${...}`), or string concatenation. A hardcoded
  string/template literal, or a `JSON.stringify()` of a purely literal
  object/array, is recognized as safe and is not flagged. (Reported from a real
  Next.js project where static JSON-LD / inline scripts were false positives.)

## [0.1.9] - 2026-08-03

### Added
- **Two rules for classes the scanner previously missed entirely** (found while
  auditing a real Next.js portfolio):
  - `ERROR_DISCLOSURE` — returning `String(err)`, `err.message`, `err.stack`, or
    an exception object to the HTTP client (internal-detail leak).
  - `HTMLI_EMAIL_TEMPLATE` — unescaped input built into an `html:` email body
    (Resend/Nodemailer/SendGrid): the same class as `innerHTML` XSS, but the
    "DOM" is the recipient's mail client.
- **Skill: a whole new reference, `logic-config-and-disclosure.md`**, plus a
  rewritten "hunt" step, teaching the audit to reliably find the bugs a scanner
  can't: client-only protections not enforced server-side (form→endpoint),
  config-vs-usage drift (dead CSP/CORS domains, unused `NEXT_PUBLIC_`/env keys),
  error disclosure, and injection into non-DOM HTML sinks. The skill now treats a
  clean scan as the *start* of the hunt and is forbidden from calling an app
  "secure" — it reports what was and was not checked.

### Fixed
- **Build/output directories are excluded by default** (`out`, `coverage`,
  `.nuxt`, `.svelte-kit`, `.output`, `.cache`, `.turbo`, and more, alongside the
  existing `dist`/`build`/`.next`/`node_modules`). Scanning a stale `out/` build
  no longer produces hundreds of false positives from bundled vendor code.
- **Minified/bundled files are skipped** (by `.min.js`/`.bundle.js` name or a
  tell-tale very-long line), killing false "critical" hits inside packed library
  JavaScript.
- `ajar/__init__.py` version was stuck at 0.1.7 (the report footer showed the
  wrong version); versions are now consistent.

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
