# Audit methodology

A professional review, not a scanner dump. Work in this order.

## 1. Recon — build a map before judging anything

Understand the app before you look for bugs. Establish:

- **Stack & frameworks** — language(s), web framework (Flask/Django/Express/
  Next.js), ORM/DB driver, template engine, auth library.
- **Entry points (sources of untrusted input):** HTTP routes / API handlers,
  form bodies, query strings, headers, cookies, file uploads, webhooks, message
  queues, CLI args, and anything read from another service.
- **Sensitive sinks:** database queries, shell/`exec`, filesystem access,
  outbound HTTP, template rendering, deserialization, auth/session decisions,
  crypto, and reads/writes of secrets.
- **Trust boundaries:** where does data cross from "attacker-controlled" to
  "trusted"? Every bug lives at a boundary.

Use Grep/Glob to list routes and handlers. Note which endpoints require auth and
which don't — the unauthenticated ones are the attack surface.

## 2. Scan — fast deterministic first pass

```bash
ajar scan <path> --format json
```

This gives leads: pattern hits, taint flows, secrets. It is a **starting point**,
never the final answer.

## 3. Verify every finding (the real work)

For each candidate, answer: *can an attacker actually trigger this, with what
input, and what happens?* Most of a good audit is here. See
[verifying-and-exploitability.md](verifying-and-exploitability.md). Say out loud
which findings are real and which are false positives, and why.

## 4. Hunt what the scanner cannot see

Regex and taint find *injection-shaped* bugs. They do **not** find:

- **Broken access control / IDOR** — can user A read/modify user B's data by
  changing an id? (The #1 real-world web vuln, and invisible to scanners.)
- **Auth logic flaws** — password reset that doesn't verify ownership, JWT trust
  bugs, privilege checks missing on some routes.
- **Business-logic abuse** — negative quantities, race conditions, replay,
  workflow steps skipped.
- **Mass assignment / over-posting** — binding request fields straight to a model.

Read the code paths for these deliberately. They are where the serious bugs are.

## 5. Fix correctly

Apply the *right* remediation per class (see the per-class references). Keep it
minimal and behavior-preserving. Confirm before anything risky (touching auth,
deleting code, changing a public API).

## 6. Re-verify

Re-run `ajar scan` and re-read the changed code. A fix can introduce a new bug.
Repeat until clean at the agreed threshold, or the rest is documented/accepted.

## 7. Report honestly

State: what was found (with severity and *why it matters*), what was fixed, what
remains, and the blunt caveat that a clean review is a strong signal — not a
guarantee. Logic and design flaws need a human and, for anything critical, a
professional pentest.
