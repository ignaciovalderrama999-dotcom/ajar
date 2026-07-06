# Auth, access control & secrets

The highest-impact real-world bugs live here — and most are **invisible to
scanners** because they're logic, not patterns. Read the code paths yourself.

---

## Broken access control / IDOR (the #1 real web vuln)

**What:** the app checks that you're *logged in* but not that you're *allowed to
touch this specific resource*.

**Hunt for it:** every handler that takes an id/slug from the request and loads a
record. Ask: *is there a check that this record belongs to the current user?*
```python
# VULNERABLE: any logged-in user can read any invoice
@app.get("/invoice/<id>")
@login_required
def invoice(id):
    return db.get_invoice(id)          # no ownership check!
```
**Test it mentally:** log in as user A, request user B's id. Do you get B's data?

**Fix — scope every query to the current user (or check ownership/role):**
```python
inv = db.get_invoice(id)
if inv.owner_id != current_user.id and not current_user.is_admin:
    abort(403)
```
Prefer queries that can't leak: `db.get_invoice(id, owner_id=current_user.id)`.
Also check **function-level** access: is every admin route actually gated? Are
there routes missing the auth decorator entirely?

## Fail-open authentication (ajar's flagship)

Auth that turns **off** when a config is missing/wrong:
```python
if os.getenv("ENV") != "production":
    auth_required = False        # unset/typo'd ENV -> wide open in prod
```
**Fix — fail closed:** default to secure; require an explicit, loudly-logged
opt-out that a missing env var can never trigger. Same for error handlers that
`return True`/grant access on exception — on any error in an authz path, **deny**.

## JWT pitfalls

- **`alg: none`** accepted → tokens need no signature → forge any user. Pin an
  explicit algorithm; reject `none`.
- **Verification disabled** (`verify_signature=False`, `verify=False`) → forged
  tokens accepted. Always verify signature **and** claims (`exp`, `aud`, `iss`).
- **Weak/hardcoded secret** for HS256 → brute-forceable. Use a strong secret from
  the environment, or RS256 with a real key.
- **Algorithm confusion** (RS256 verified as HS256 using the public key as the
  HMAC secret) → forge tokens. Pin the expected algorithm explicitly.

## Sessions & cookies

Session cookies must be `HttpOnly` (no JS access → XSS can't steal them),
`Secure` (HTTPS only), and `SameSite=Lax`/`Strict` (CSRF defense). Rotate the
session id on login. Set a sane expiry.

## Secrets

**Hardcoded** keys/tokens/passwords: move to environment variables or a secrets
manager, and **rotate** anything that was committed (git history keeps it
forever — see also removing it from history). ajar's entropy check flags
random-looking strings even with no known pattern; confirm each *is* a secret
(not a hash/UUID/asset fingerprint) before acting.

**High-value secrets to prioritize:** live payment keys (Stripe `sk_live_`),
cloud keys (AWS `AKIA...`), GitHub/Google tokens, private keys, DB connection
strings with passwords, and — in web bundles — anything shipped to the client.

## Weak cryptography

- **Broken/for-passwords hashing:** MD5/SHA1 are collision-broken and too fast.
  Use SHA-256+ for integrity, and a slow salted KDF (**argon2**, bcrypt, scrypt)
  for passwords — never plain hashing for passwords.
- **Broken ciphers/modes:** DES, RC4, and ECB mode leak. Use AES-256-GCM or a
  high-level lib (libsodium, Fernet).
- **Non-cryptographic randomness for security:** `random`/`Math.random` are
  predictable → don't use them for tokens, session ids, OTPs, password resets.
  Use `secrets`/`os.urandom` (Python) or `crypto.randomBytes`/
  `crypto.getRandomValues` (JS).
