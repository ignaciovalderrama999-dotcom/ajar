# Cross-file & logic classes — the concrete technique

These are the bugs a pattern scanner cannot see because they live in **logic** or
in the **relationship between two files**. A scanner reads one line at a time; you
reason across files. Work each class with the recipe below. Every step is a real
finding class that a clean scan will happily hide.

---

## 1. Client-enforced-only protections (form → endpoint)

**The bug:** an anti-abuse control exists in the frontend but the server never
re-checks it, so hitting the API directly bypasses it.

**Recipe:**
1. In the UI/form component, list every protection: honeypot field, submit
   timer/delay, rate limit, captcha, required/format validation, min-length,
   "disabled until valid" button, auth gate.
2. Find the endpoint the form posts to (`fetch("/api/…")`, `action=`, the mutation).
3. Open that handler and check, for **each** protection, whether the server
   re-validates it. Honeypot → does the handler reject when the hidden field is
   filled? Timer → does the handler reject submissions that are too fast? Rate
   limit → is it enforced server-side (not just a disabled button)?
4. If the server doesn't enforce it, it's a real bug: *"protection X exists only
   client-side; POST directly to `/api/…` bypasses it."* Fix: enforce on the server.

**Why the scanner misses it:** the form and the endpoint are two different files;
there is no single-line pattern for "this check is missing over there."

---

## 2. Configuration vs. actual usage (config → codebase)

**The bug:** security config references integrations/domains that no longer exist
in the code — dead policy that widens attack surface and signals an unmaintained
config.

**Recipe (CSP / CORS / allow-lists):**
1. Extract every domain/origin from the policy (e.g. each host in
   `Content-Security-Policy`, each allowed CORS origin).
2. For each one, grep the codebase for that domain.
3. A domain allowed by the policy but used **nowhere** is dead — from a removed
   integration. Report it and remove it from the policy.

**Recipe (dead secrets / env keys):**
1. List every key in `.env`, `.env.local`, and every `NEXT_PUBLIC_*` / config var.
2. Grep each key name across the codebase.
3. Keys referenced **nowhere** are leftovers from abandoned integrations. Delete
   them; rotate any that were ever real credentials. Flag `NEXT_PUBLIC_*`
   especially — those ship to the browser, so a stale one is needless exposure.

**ajar now does part of this for you:** the scanner's project-level pass emits
`UNUSED_ENV_KEY` / `UNUSED_PUBLIC_ENV_KEY` for `.env` keys used nowhere, and
`DEAD_CSP_DOMAIN` for CSP domains referenced nowhere. Treat those as confirmed
leads. You still hunt the cases it can't (dynamic `process.env[name]`, domains
built at runtime, allow-lists in formats it doesn't parse).

---

## 3. Information / error disclosure (handler → response)

**The bug:** a handler returns internal error detail to the client.

**Recipe:**
1. In each catch block / error path, look at what goes into the response:
   `String(err)`, `err.message`, `err.stack`, or the exception object itself.
2. Any of those in the HTTP body leaks file paths, library versions, SQL
   fragments, and stack frames — a map for the attacker.
3. Fix: log the full error server-side with a correlation id; return a generic
   message (`{ error: "Internal error", id }`) to the client.

The scanner's `ERROR_DISCLOSURE` rule catches the obvious `res.json({...err...})`
cases; you catch the ones behind a helper or a re-thrown wrapper.

---

## 4. Injection into non-DOM HTML sinks (input → HTML that isn't the page)

**The bug:** unescaped user input built into HTML that the scanner's
`innerHTML`/`dangerouslySetInnerHTML` rules don't watch.

**Where to look:** an email `html:` body (Resend, Nodemailer, SendGrid), a
generated PDF, a server-rendered template string, an SVG built from input.

**Recipe:**
1. Find every place an `html`/body string is built from a variable (template
   literal with `${…}`, or string concatenation).
2. Trace whether any interpolated value is user-controlled and unescaped.
3. Treat it exactly like `innerHTML`: escape the value (an HTML-escaping helper
   or an auto-escaping template engine) before it goes in.

The scanner's `HTMLI_EMAIL_TEMPLATE` rule flags the email case; you generalize it
to PDFs, templates, and any other HTML-shaped sink.

---

## The mindset

When the scan comes back with nothing, that is the signal to slow down and work
this file — not to declare victory. The bugs that matter most are the ones no
regex can reach, and they are usually still there.
