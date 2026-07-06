# Web & Next.js specifics

Modern React/Next.js apps have their own footguns. Check these deliberately.

## Secrets leaked to the browser via `NEXT_PUBLIC_`

Any env var prefixed `NEXT_PUBLIC_` is **inlined into the JavaScript bundle sent
to every visitor**. A secret there is world-readable.
```
NEXT_PUBLIC_STRIPE_SECRET=sk_live_...   # LEAKED to every browser
```
**Fix:** drop the prefix so it stays server-side; read it only in server code
(Route Handlers, Server Components, Server Actions, `getServerSideProps`).
**Hunt:** grep `NEXT_PUBLIC_` and check each — is it truly public (a URL, a
publishable key) or a secret? Also check that no secret is used in a Client
Component (`"use client"`), where it would be bundled.

## Server Actions & Route Handlers = real endpoints

`"use server"` actions and `app/api/**/route.ts` handlers are **public HTTP
endpoints**. Treat every argument as attacker-controlled:
- **Authorize inside the action**, not just in the UI that calls it. The UI can
  be bypassed; the action is directly callable.
- **Validate input** (zod/valibot) — never trust the shape or values.
- Watch for **IDOR** here just like any endpoint (see auth-and-secrets.md).

## SSR data over-exposure

`getServerSideProps` / Server Components serialize whatever you return into the
page. Returning a full user object leaks `passwordHash`, internal flags, other
users' fields. **Return only the fields the page needs.** Same for API responses.

## XSS in React

React escapes `{value}` by default — good. The holes:
- `dangerouslySetInnerHTML` (sanitize with DOMPurify).
- `href={userUrl}` allowing `javascript:` URLs (validate scheme).
- Injecting into `<script>`, `<style>`, or `dangerouslySetInnerHTML` JSON-LD.

## CORS

`Access-Control-Allow-Origin: *` **with credentials** lets any site make
authenticated requests as the victim. Use an explicit allow-list of trusted
origins; never reflect the `Origin` header blindly.

## Security headers (defense in depth)

Set via `next.config.js` headers or middleware:
- **Content-Security-Policy** — the strongest XSS mitigation. Avoid
  `unsafe-inline`/`unsafe-eval`; use nonces/hashes.
- **Strict-Transport-Security** (HSTS), **X-Content-Type-Options: nosniff**,
  **X-Frame-Options / frame-ancestors** (clickjacking), **Referrer-Policy**.

## CSRF

State-changing requests that rely on cookies need CSRF protection (tokens or
`SameSite` cookies). Next.js Server Actions have some built-in protection, but
custom cookie-authed POST routes do not — add it.

## Open redirect

`redirect(req.query.next)` / `NextResponse.redirect(userUrl)` → phishing from
your trusted domain. Redirect only to a fixed allow-list of internal paths.

## Dependencies & supply chain

`npm audit` for known-vulnerable packages; watch for typosquatted or abandoned
deps, and postinstall scripts in untrusted packages. Lockfile committed.
