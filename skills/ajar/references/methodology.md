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
- **Integrations & config inventory:** list the security config (CSP, CORS,
  cookies, headers), every third-party integration, and every `.env` /
  `NEXT_PUBLIC_*` key. You will cross-reference these against actual code usage
  in step 4 — dead entries are a class of finding on their own.

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

## 4. Hunt what the scanner cannot see (the real audit)

**A clean scan is the START of this step, not the end.** The scanner finds
*injection-shaped* patterns in single lines. Most serious bugs are not shaped
like that — they live in **logic** and in the **relationship between two files**.
Assume the scan missed something and go prove it. Never conclude "looks secure"
because the scanner was quiet — that is exactly when you dig harder.

For a small app you can and should read every route handler end to end. Work
through **all** of these classes explicitly — do not stop at the scanner's list:

### Logic & access (no pattern can see these)
- **Broken access control / IDOR** — can user A read/modify user B's data by
  changing an id? (The #1 real-world web vuln.)
- **Auth logic flaws** — password reset that doesn't verify ownership, JWT trust
  bugs, privilege checks missing on some routes.
- **Business-logic abuse** — negative quantities, race conditions, replay,
  workflow steps skipped.
- **Mass assignment / over-posting** — binding request fields straight to a model.

### Client-enforced-only protections (a two-file bug — check every protection)
A control that exists **only in the frontend** is not a control. For every
anti-abuse measure you see in the UI — **honeypot field, submit timer / delay,
rate limit, captcha, required-field or format validation, disabled button, auth
gate** — open the **API endpoint it posts to** and confirm the server re-checks
it. If the handler doesn't, an attacker hits the endpoint directly and skips it.
Trace the pair **form → endpoint**, not the form alone.

### Configuration vs. actual usage (cross-reference, don't read in isolation)
Config drifts out of sync with code. For each entry in security config, verify
it still matches reality:
- **CSP / CORS / allow-lists** — grep each allowed domain against the codebase.
  A domain in `Content-Security-Policy` or an allowed origin that appears
  **nowhere in the code** is dead config from a removed integration — remove it
  (it's needless attack surface and a sign nobody is maintaining the policy).
- **Dead / unused secrets & env keys** — list every `.env` / `NEXT_PUBLIC_*` /
  config variable and grep for its use. Keys referenced **nowhere** are leftover
  from abandoned integrations: delete them (and rotate if they were ever real).
  `NEXT_PUBLIC_*` values ship to the browser, so a stale one is exposed for no
  reason.

### Output & error handling
- **Information / error disclosure** — does any handler return `String(err)`,
  `err.message`, `err.stack`, or an exception object to the client? That leaks
  file paths, versions, and SQL to an attacker. Log server-side, return a
  generic message. (The scanner's `ERROR_DISCLOSURE` rule catches the obvious
  cases; you catch the rest.)
- **Injection into non-DOM HTML sinks** — the scanner sees `innerHTML` /
  `dangerouslySetInnerHTML`. It largely can't see the *same* bug when unescaped
  input is built into an **email `html:` body** (Resend/Nodemailer/SendGrid), a
  generated PDF, or a server-rendered template string. Treat every HTML-shaped
  sink like `innerHTML` and check for escaping.

See [logic-config-and-disclosure.md](logic-config-and-disclosure.md) for the
concrete grep-driven technique for each of the cross-file classes above.

Read the code paths for all of these deliberately. They are where the bugs the
scanner (and a careless reviewer) miss actually live.

## 5. Fix correctly

Apply the *right* remediation per class (see the per-class references). Keep it
minimal and behavior-preserving. Confirm before anything risky (touching auth,
deleting code, changing a public API).

## 6. Re-verify

Re-run `ajar scan` and re-read the changed code. A fix can introduce a new bug.
Repeat until clean at the agreed threshold, or the rest is documented/accepted.

## 7. Report honestly

**Never tell the user their app is "secure" or "safe."** You cannot prove the
absence of bugs, and a false all-clear is the worst outcome a security review can
produce — it makes the user ship with confidence they haven't earned.

Instead, always report:
- **What you found** (with severity and *why it matters*).
- **What you fixed**, and what remains.
- **What you actually checked** and, explicitly, **what you did NOT check** —
  name the classes from step 4 you couldn't fully cover (business logic,
  access control, cross-file flows, config-vs-usage) so the boundary is clear.
- The blunt caveat: a review with no findings means *"no issues found at this
  depth"*, **not** *"this is secure."* Logic and design flaws need a human and,
  for anything critical, a professional pentest.

If you genuinely found nothing, be more suspicious, not less — re-read step 4 and
make sure you actually hunted the logic and cross-file classes, because that is
usually where the real bug is hiding when the patterns come back clean.
