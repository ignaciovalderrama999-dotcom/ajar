# Contributing to ajar

Thanks for helping keep more doors closed! Contributions are welcome — especially
**new detection rules** for real-world fail-open and misconfiguration patterns.

## Ground rules

ajar is a **defensive** tool. Every contribution must keep it that way:

- Rules **detect and explain** risk — they never generate exploits, payloads, or
  offensive tooling.
- Keep the tone educational: a good rule teaches *why* something is dangerous and
  *how* to fix it.

## Getting set up

```bash
git clone https://github.com/your-username/ajar
cd ajar
pip install -e ".[dev]"
pytest            # run the test suite
ruff check .      # lint
```

## Adding a rule

Rules live in `ajar/rules/*.yml`. Each rule is plain, auditable YAML:

```yaml
rules:
  - id: UNIQUE_UPPER_SNAKE_ID
    name: Short human-readable name
    severity: high            # info | low | medium | high | critical
    category: fail-open       # or insecure-defaults | injection | denial-of-service | secrets
    message: One-line description shown in output.
    pattern: '(?i)your python regex here'
    why: How an attacker abuses this (required).
    fix: How to close the door (required).
    references:
      - https://owasp.org/...
    extensions: [".js", ".ts"]   # optional: restrict to certain file types
```

Guidelines:

1. **Every rule needs a `why` and a `fix`** — the test suite enforces this.
2. **Prefer precision over noise.** Add a test showing it fires on the bad case
   *and* stays quiet on the safe case (e.g. a parameterized query).
3. Use `(?i)` for case-insensitive matches where it helps.
4. Keep ids in `UPPER_SNAKE_CASE` and unique.

## Adding a test

Add cases to `tests/test_scanner.py`. Both a true-positive and a
true-negative are expected for a new rule.

## Submitting

1. Fork and create a branch.
2. Make your change; run `pytest` and `ruff check .`.
3. Open a PR describing the pattern and linking a reference (OWASP/CWE) where
   possible.

By contributing you agree your work is licensed under the project's
[Apache License 2.0](LICENSE).
