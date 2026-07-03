# ajar rule catalog

ajar ships **56 rules** across **5 categories**. Every rule explains the risk and the fix. Rules are plain YAML in [`ajar/rules/`](ajar/rules/) — audit or extend them freely.

> Regenerate this file with: `ajar rules --format md > RULES.md`

## denial-of-service  (5)

### `DOS_REGEX_FROM_USER_INPUT` — Regex compiled from user input

**Severity:** high

A regex pattern is built from request/user input.

- **Why it matters:** If users control the regex itself, they can supply a catastrophic pattern that hangs your server (ReDoS) — a cheap way to deny service to everyone.
- **How to fix:** Never compile untrusted input as a regex. Validate against a fixed set of allowed patterns, or use plain string operations instead.
- **Reference:** https://cwe.mitre.org/data/definitions/1333.html

### `DOS_DECOMPRESSION_BOMB` — Archive extracted without size limits

**Severity:** medium

An archive is fully extracted without checking its size.

- **Why it matters:** A tiny "zip bomb" can expand to gigabytes and fill the disk or exhaust memory, crashing the host (decompression-bomb denial of service).
- **How to fix:** Inspect each member's declared size and the running total before extracting; cap the number of files and total bytes, and reject anything over the limit.
- **Reference:** https://cwe.mitre.org/data/definitions/409.html

### `DOS_NO_REQUEST_TIMEOUT` — Outbound HTTP call without a timeout

**Severity:** medium

An HTTP request is made without a timeout.

- **Why it matters:** With no timeout, a slow or unresponsive server can make this call hang forever, tying up a worker/thread. Enough hung requests exhaust your pool and take the whole service down (a slowloris-style denial of service).
- **How to fix:** Always pass an explicit timeout, e.g. requests.get(url, timeout=5).
- **Reference:** https://owasp.org/www-community/attacks/Denial_of_Service
- **Reference:** https://cwe.mitre.org/data/definitions/400.html

### `DOS_NO_URLLIB_TIMEOUT` — urlopen without a timeout

**Severity:** medium

urllib urlopen is called without a timeout.

- **Why it matters:** Like any network call, urlopen without a timeout can block indefinitely and exhaust your worker pool under load.
- **How to fix:** Pass a timeout, e.g. urlopen(url, timeout=5).
- **Reference:** https://cwe.mitre.org/data/definitions/400.html

### `DOS_REDOS_NESTED_QUANTIFIER` — Regex vulnerable to catastrophic backtracking (ReDoS)

**Severity:** medium

A regex uses nested quantifiers that can backtrack catastrophically.

- **Why it matters:** Patterns like (a+)+ or (.*)* can take exponential time on a crafted input. A single malicious string can pin a CPU core at 100% and hang the request (regular-expression denial of service, ReDoS).
- **How to fix:** Rewrite the regex to avoid nested quantifiers, anchor it, or use a linear engine (e.g. Google RE2) for untrusted input.
- **Reference:** https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- **Reference:** https://cwe.mitre.org/data/definitions/1333.html

## fail-open  (5)

### `FAILOPEN_AUTH_ENV_BYPASS` — Auth disabled outside production

**Severity:** critical

Authentication is switched off based on an environment name.

- **Why it matters:** If the environment variable that flips this is missing or misspelled in production, the app boots wide open with no authentication. Attackers do not need a bug — the default IS the vulnerability.
- **How to fix:** Fail closed: default authentication to ON and require an explicit, loudly-logged opt-out that is impossible to trigger by a missing env var.
- **Reference:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- **Reference:** https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

### `FAILOPEN_ENV_NOT_PRODUCTION` — Security relaxed when ENV is not 'production'

**Severity:** high

A security control is gated on the environment NOT being production.

- **Why it matters:** Comparing against 'production' means any unset, typo'd, or unexpected env value (staging, prod-eu, empty string) takes the insecure branch. The secure path should be the default, not a string match you have to get right.
- **How to fix:** Invert the check: assume production. Only relax controls when an explicit allow-list value is present, and log loudly when you do.
- **Reference:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

### `FAILOPEN_EXCEPT_ALLOW` — Access granted inside an exception handler

**Severity:** high

An error handler appears to grant access or return success on failure.

- **Why it matters:** If the check that determines access throws (network blip, malformed token, downstream outage), catching the error and returning True means a failure becomes a free pass. Attackers can force failures on purpose.
- **How to fix:** Fail closed: on any error in an authorization path, deny access and alert.
- **Reference:** https://cwe.mitre.org/data/definitions/636.html

### `FAILOPEN_TLS_VERIFY_DEFAULT` — TLS verification defaults to off

**Severity:** high

Certificate verification defaults to disabled via config/env.

- **Why it matters:** A default of verify=False means that if the env toggle is absent, traffic flows without certificate validation — every request is open to a man-in-the-middle. The insecure state is the one you get by doing nothing.
- **How to fix:** Default certificate verification to ON. Never accept an env var whose absence disables TLS validation.
- **Reference:** https://cwe.mitre.org/data/definitions/295.html

### `FAILOPEN_DEFAULT_ALLOW` — Default policy is allow

**Severity:** medium

A policy/permission default resolves to allow/open rather than deny.

- **Why it matters:** When a rule does not match, the safe answer is 'deny'. A default of 'allow' means every gap in your policy coverage is an opening.
- **How to fix:** Make deny the default. Grant access only on an explicit, positive match.
- **Reference:** https://owasp.org/www-community/Access_Control

## injection  (23)

### `SQLI_CONCAT` — SQL query built with string concatenation or %

**Severity:** critical

A SQL execute/query call concatenates or %-formats a string.

- **Why it matters:** Gluing user input into a query string with + or % lets an attacker inject SQL. This is the single most common serious web vulnerability.
- **How to fix:** Never build SQL by string. Use parameterized/prepared statements provided by your driver or ORM.
- **Reference:** https://owasp.org/Top10/A03_2021-Injection/

### `SQLI_FSTRING` — SQL query built with an f-string

**Severity:** critical

An f-string is passed to a SQL execute/query call.

- **Why it matters:** An f-string splices variables straight into SQL text. If any of those values comes from a user, they can rewrite the query — read other users'' data, dump the whole table, or drop it entirely (SQL injection).
- **How to fix:** Use parameterized queries: pass placeholders (?, %s, or :name) and hand the values as a separate argument so the database never treats them as SQL.
- **Reference:** https://owasp.org/Top10/A03_2021-Injection/
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### `SQLI_JS_TEMPLATE` — SQL query built with a template literal

**Severity:** critical

A JS/TS query uses a template literal with interpolation.

- **Why it matters:** A `${...}` inside a query template splices values into SQL. User input here is a classic SQL injection vector in Node apps.
- **How to fix:** Use parameterized queries ($1, ?, or named params) from your DB client, not template-literal interpolation.
- **Reference:** https://owasp.org/Top10/A03_2021-Injection/

### `CMDI_EVAL_EXEC` — Dynamic code execution (eval/exec)

**Severity:** high

eval() or exec() is used to run code at runtime.

- **Why it matters:** If any part of the evaluated string is user-controlled, eval/exec run attacker code with your program''s privileges (remote code execution).
- **How to fix:** Remove eval/exec. Use safe alternatives: ast.literal_eval for data, a dispatch dict for behavior, or a real parser.
- **Reference:** https://cwe.mitre.org/data/definitions/95.html

### `CMDI_OS_SYSTEM` — os.system with a built string

**Severity:** high

os.system is called with a concatenated/formatted string.

- **Why it matters:** os.system hands the whole string to the shell. Any user input in it can inject additional commands.
- **How to fix:** Use subprocess with an argument list and shell=False. Avoid os.system for anything involving external input.
- **Reference:** https://cwe.mitre.org/data/definitions/78.html

### `CMDI_SHELL_TRUE` — Subprocess run with shell=True

**Severity:** high

A subprocess call uses shell=True.

- **Why it matters:** shell=True runs the command through the system shell, so any user-supplied part can inject extra commands with ; | && $(...). This is OS command injection.
- **How to fix:** Pass the command as a list of arguments and leave shell=False (the default). Never build the command line by concatenating user input.
- **Reference:** https://owasp.org/Top10/A03_2021-Injection/
- **Reference:** https://cwe.mitre.org/data/definitions/78.html

### `CODE_EXEC_NEW_FUNCTION` — Dynamic code execution via new Function

**Severity:** high

new Function() compiles a string into runnable code.

- **Why it matters:** Like eval, new Function turns a string into executing code; user input here is remote code execution.
- **How to fix:** Remove it. Use a lookup table or a real parser instead of compiling code at runtime.
- **Reference:** https://cwe.mitre.org/data/definitions/95.html

### `DESERIAL_PICKLE` — Untrusted deserialization with pickle

**Severity:** high

pickle.load/loads deserializes data.

- **Why it matters:** pickle executes arbitrary code while unpickling. Feeding it attacker data is remote code execution.
- **How to fix:** Never unpickle untrusted data. Use JSON for data interchange, or a safe schema (e.g. pydantic) for validation.
- **Reference:** https://cwe.mitre.org/data/definitions/502.html

### `DESERIAL_YAML_LOAD` — Unsafe yaml.load

**Severity:** high

yaml.load is called without the safe loader.

- **Why it matters:** Default yaml.load can construct arbitrary Python objects, which is code execution on malicious input.
- **How to fix:** Use yaml.safe_load(...) (or Loader=yaml.SafeLoader) for any untrusted YAML.
- **Reference:** https://cwe.mitre.org/data/definitions/502.html

### `PATH_TRAVERSAL_OPEN` — File path built from request input

**Severity:** high

A file is opened using a path taken from user input.

- **Why it matters:** If users control the path, "../../etc/passwd" style input lets them read or write files outside the intended directory (path traversal).
- **How to fix:** Resolve the final path and confirm it stays inside an allowed base directory; reject any input containing path separators or "..".
- **Reference:** https://owasp.org/www-community/attacks/Path_Traversal

### `SQLI_FORMAT_METHOD` — SQL query built with .format()

**Severity:** high

A SQL keyword appears in a string that calls .format().

- **Why it matters:** .format() interpolates values into the query text just like concatenation, opening the door to SQL injection when any argument is user-controlled.
- **How to fix:** Replace .format() with parameterized query placeholders.
- **Reference:** https://owasp.org/Top10/A03_2021-Injection/

### `SSRF_FETCH_USER_URL` — fetch/axios to a user-controlled URL

**Severity:** high

An outbound request uses a URL derived from the request/input.

- **Why it matters:** If users control the target URL, they can make your server (in a Next.js API route or server action) reach internal services or cloud metadata endpoints — server-side request forgery (SSRF).
- **How to fix:** Validate the URL against an allow-list of hosts and schemes, and block private/internal IP ranges before fetching.
- **Reference:** https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/

### `SSRF_USER_URL` — Server-side request to a user-controlled URL

**Severity:** high

An outbound HTTP call takes a URL derived from the request.

- **Why it matters:** If users control the target URL, they can make your server call internal systems, cloud metadata endpoints, or private services (SSRF) that they could not reach directly.
- **How to fix:** Validate the URL against an allow-list of hosts/schemes, resolve and block private/internal IP ranges, and disable redirects for these calls.
- **Reference:** https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/

### `SSTI_RENDER_STRING` — Server-side template built from a string

**Severity:** high

render_template_string is used, risking template injection.

- **Why it matters:** Passing user input into a template string lets attackers execute template expressions (SSTI), which often escalates to full code execution.
- **How to fix:** Render from static template files and pass user data only as escaped variables — never build the template body from input.
- **Reference:** https://owasp.org/www-community/attacks/Server_Side_Template_Injection

### `XSS_DOCUMENT_WRITE` — document.write with dynamic content

**Severity:** high

document.write() renders content directly into the page.

- **Why it matters:** document.write of anything user-influenced (URL, hash, input) executes injected scripts — reflected cross-site scripting (XSS).
- **How to fix:** Build the DOM with textContent / safe framework rendering, or sanitize with a vetted library (DOMPurify) before inserting HTML.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### `XSS_INNERHTML` — Unescaped assignment to innerHTML

**Severity:** high

Content is assigned to innerHTML/outerHTML.

- **Why it matters:** Writing user data into innerHTML executes any <script> or event handler it contains — cross-site scripting (XSS), which can steal sessions and act as the victim.
- **How to fix:** Use textContent for text, or sanitize HTML with a vetted library (e.g. DOMPurify) before inserting it.
- **Reference:** https://owasp.org/Top10/A03_2021-Injection/
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### `XSS_TEMPLATE_AUTOESCAPE_OFF` — Template autoescaping disabled

**Severity:** high

HTML autoescaping is turned off in a template engine.

- **Why it matters:** Autoescaping is what stops user data from being interpreted as HTML. Turning it off (or marking content "safe") reintroduces XSS.
- **How to fix:** Keep autoescaping on. Only mark content safe after sanitizing it, and never mark user input safe.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### `XXE_EXTERNAL_ENTITIES` — XML parser resolves external entities (XXE)

**Severity:** high

An XML parser is configured to resolve external entities.

- **Why it matters:** With external entities enabled, a crafted XML document can read local files, reach internal services (SSRF), or exhaust memory (billion laughs) — XML External Entity injection (XXE).
- **How to fix:** Disable external entities and DTD processing. In Python use defusedxml; in Java set the secure-processing features to disallow DOCTYPE/entities.
- **Reference:** https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

### `OPEN_REDIRECT` — Redirect to a user-controlled target

**Severity:** medium

A redirect uses a destination taken from the request.

- **Why it matters:** An attacker can craft a link to your trusted site that bounces the victim to a phishing page (open redirect), lending your domain''s credibility.
- **How to fix:** Redirect only to a fixed allow-list of internal paths; never to a raw user-supplied URL.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### `OPEN_REDIRECT_JS` — Redirect to a user-controlled target (JS/Next.js)

**Severity:** medium

A redirect destination comes from the request/input.

- **Why it matters:** An attacker can craft a link on your trusted domain that bounces the victim to a phishing site (open redirect).
- **How to fix:** Redirect only to a fixed allow-list of internal paths, never to a raw user-supplied URL.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

### `XSS_DANGEROUS_HTML` — React dangerouslySetInnerHTML

**Severity:** medium

dangerouslySetInnerHTML injects raw HTML into the DOM.

- **Why it matters:** This bypasses React''s built-in escaping. Unsanitized user content here becomes stored or reflected XSS.
- **How to fix:** Render as text where possible, or sanitize with DOMPurify before passing the HTML in.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

### `XSS_JS_HREF_JAVASCRIPT` — javascript: URL sink

**Severity:** medium

A "javascript:" URL is assigned, which executes code.

- **Why it matters:** A javascript: URL runs arbitrary script in the page context; if any part comes from user input it becomes XSS.
- **How to fix:** Never use javascript: URLs. Attach event handlers in code instead.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

### `XXE_UNSAFE_PARSER` — XML parsed with a non-hardened parser

**Severity:** medium

XML is parsed with a standard library that is XXE-prone by default.

- **Why it matters:** Several standard XML parsers process DTDs/entities by default, exposing the app to XXE when the XML comes from an untrusted source.
- **How to fix:** Parse untrusted XML with defusedxml (Python) or an equivalent hardened configuration that disables DTDs and external entities.
- **Reference:** https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

## insecure-defaults  (13)

### `JWT_NONE_ALGORITHM` — JWT accepts the 'none' algorithm

**Severity:** critical

A JWT is configured to allow the "none" signing algorithm.

- **Why it matters:** With alg "none" a token needs no signature, so an attacker can forge any token (become any user, an admin) just by crafting the payload.
- **How to fix:** Pin an explicit strong algorithm (e.g. RS256 or HS256) and reject "none". Never derive the verification algorithm from the token header.
- **Reference:** https://cwe.mitre.org/data/definitions/347.html

### `DEFAULT_DEBUG_ON` — Debug mode enabled

**Severity:** high

Debug mode is turned on, which can leak stack traces and internals.

- **Why it matters:** Debug mode exposes stack traces, environment variables, and often an interactive console to anyone who triggers an error in production.
- **How to fix:** Default DEBUG to False and drive it from an explicit env var that is only true in local development.
- **Reference:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

### `DEFAULT_TLS_VERIFY_FALSE` — TLS certificate verification disabled

**Severity:** high

A request is made with certificate verification explicitly disabled.

- **Why it matters:** verify=False disables certificate validation, silently accepting forged or self-signed certificates and enabling man-in-the-middle interception.
- **How to fix:** Remove verify=False. If you must trust an internal CA, pass its cert bundle path instead of turning verification off.
- **Reference:** https://cwe.mitre.org/data/definitions/295.html

### `JWT_VERIFY_DISABLED` — JWT signature verification disabled

**Severity:** high

A JWT is decoded without verifying its signature.

- **Why it matters:** Skipping signature verification means any tampered or forged token is accepted, defeating the entire point of a signed token.
- **How to fix:** Always verify the signature and the claims (exp, aud, iss). Never decode with verification turned off outside a controlled test.
- **Reference:** https://cwe.mitre.org/data/definitions/347.html

### `WEAK_CIPHER` — Weak or broken cipher / mode

**Severity:** high

A broken cipher (DES/RC4) or insecure mode (ECB) is used.

- **Why it matters:** DES and RC4 are broken, and ECB mode leaks patterns in the plaintext. Data "encrypted" this way can often be recovered.
- **How to fix:** Use AES-256 in an authenticated mode (GCM) or a high-level library (libsodium / cryptography's Fernet). Never use ECB for real data.
- **Reference:** https://cwe.mitre.org/data/definitions/327.html

### `CSP_UNSAFE` — Content-Security-Policy allows unsafe-inline/unsafe-eval

**Severity:** medium

A CSP directive permits unsafe-inline or unsafe-eval.

- **Why it matters:** unsafe-inline and unsafe-eval let injected inline scripts run, which largely defeats the XSS protection a CSP is supposed to provide.
- **How to fix:** Remove unsafe-inline/unsafe-eval; use nonces or hashes for the scripts you trust, and move inline handlers into separate files.
- **Reference:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

### `CSRF_PROTECTION_DISABLED` — CSRF protection disabled

**Severity:** medium

Cross-site request forgery protection is turned off.

- **Why it matters:** Without CSRF protection, a malicious site can make a logged-in victim's browser perform state-changing actions on your app without their consent.
- **How to fix:** Keep CSRF protection enabled for state-changing routes; use per-request tokens or the SameSite cookie attribute. Only exempt endpoints that are safe by design (e.g. stateless APIs with token auth) and document why.
- **Reference:** https://owasp.org/www-community/attacks/csrf

### `DEFAULT_BIND_ALL_INTERFACES` — Service bound to all network interfaces

**Severity:** medium

A service binds to 0.0.0.0, exposing it on every network interface.

- **Why it matters:** Binding to 0.0.0.0 exposes a service beyond localhost. Combined with a weak or default auth config, it becomes reachable from the whole network.
- **How to fix:** Bind to 127.0.0.1 for local-only services, or put the service behind an authenticated gateway if it must be reachable.
- **Reference:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

### `DEFAULT_MD5_SHA1_HASH` — Weak hash used for security

**Severity:** medium

A broken hash function (MD5/SHA1) is used where security matters.

- **Why it matters:** MD5 and SHA1 are collision-broken. For passwords they are also far too fast, making brute force cheap.
- **How to fix:** Use SHA-256+ for integrity, and a slow salted KDF (bcrypt, scrypt, argon2) for passwords.
- **Reference:** https://cwe.mitre.org/data/definitions/327.html

### `DEFAULT_PERMISSIVE_CORS` — CORS allows any origin

**Severity:** medium

CORS is configured to allow all origins (*).

- **Why it matters:** A wildcard CORS origin lets any website make authenticated requests to your API from a victim's browser, enabling data theft across origins.
- **How to fix:** Replace * with an explicit allow-list of trusted origins.
- **Reference:** https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

### `DEFAULT_WORLD_WRITABLE` — World-writable file permissions

**Severity:** medium

File permissions grant write access to everyone (chmod 777 / 666).

- **Why it matters:** World-writable files let any local user or compromised process modify code, config, or data — a common privilege-escalation stepping stone.
- **How to fix:** Grant the least permission needed (typically 0o644 for files, 0o755 for executables) and restrict ownership.
- **Reference:** https://cwe.mitre.org/data/definitions/732.html

### `INSECURE_RANDOM_FOR_SECRET` — Weak randomness used for a security value

**Severity:** medium

A non-cryptographic RNG is used for a token/password/secret.

- **Why it matters:** random / Math.random are predictable. Using them for tokens, OTPs, session ids or passwords lets an attacker guess or reproduce the value.
- **How to fix:** Use a cryptographically secure source: Python secrets module, os.urandom, or crypto.randomBytes / crypto.getRandomValues in JS.
- **Reference:** https://cwe.mitre.org/data/definitions/338.html

### `DEFAULT_INSECURE_COOKIE` — Session cookie without Secure/HttpOnly

**Severity:** low

A cookie flag that protects sessions is explicitly disabled.

- **Why it matters:** Disabling Secure sends session cookies over plain HTTP; disabling HttpOnly exposes them to cross-site-scripting theft.
- **How to fix:** Set Secure=True and HttpOnly=True on session cookies; add SameSite too.
- **Reference:** https://owasp.org/www-community/controls/SecureCookieAttribute

## secrets  (10)

### `SECRET_AWS_ACCESS_KEY` — Hardcoded AWS access key

**Severity:** critical

An AWS access key ID appears to be hardcoded.

- **Why it matters:** A committed AWS key grants direct API access to the account. Bots scrape public repos for exactly this pattern within minutes of a push.
- **How to fix:** Revoke the key immediately, rotate it, and load credentials from the environment or a secrets manager instead.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `SECRET_GITHUB_TOKEN` — Hardcoded GitHub token

**Severity:** critical

A GitHub personal access / OAuth token appears to be hardcoded.

- **Why it matters:** A leaked GitHub token grants API access to repositories and org resources. Bots scrape public code for this exact pattern within minutes.
- **How to fix:** Revoke and regenerate the token immediately; load it from the environment or a secrets manager.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `SECRET_PRIVATE_KEY` — Private key material

**Severity:** critical

A PEM private key block is embedded in source.

- **Why it matters:** A leaked private key lets an attacker impersonate your service, decrypt traffic, or sign malicious artifacts.
- **How to fix:** Remove the key, rotate it, and store it in a secrets manager or an untracked file referenced by path.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `SECRET_STRIPE_KEY` — Hardcoded Stripe live key

**Severity:** critical

A live Stripe secret key appears to be hardcoded.

- **Why it matters:** A live Stripe secret key can move real money and read customer/payment data. This is one of the highest-impact secrets to leak.
- **How to fix:** Roll the key in the Stripe dashboard now and load it only server-side from a secret store.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `NEXT_PUBLIC_SECRET` — Secret exposed to the browser via NEXT_PUBLIC_

**Severity:** high

A NEXT_PUBLIC_ variable names a secret and is shipped to the client.

- **Why it matters:** In Next.js, any env var prefixed NEXT_PUBLIC_ is inlined into the JavaScript bundle sent to every visitor. Putting a secret there leaks it to the whole world.
- **How to fix:** Drop the NEXT_PUBLIC_ prefix so the value stays server-side, and read it only in server code (API routes, server components, server actions).
- **Reference:** https://nextjs.org/docs/app/building-your-application/configuring/environment-variables

### `SECRET_GENERIC_ASSIGNMENT` — Hardcoded credential assignment

**Severity:** high

A password/secret/token is assigned a hardcoded literal value.

- **Why it matters:** Hardcoded credentials end up in version history forever, are shared with everyone who clones the repo, and cannot be rotated without a code change.
- **How to fix:** Load secrets from environment variables or a secrets manager. Never commit real credentials — use placeholders in examples.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `SECRET_GOOGLE_API_KEY` — Hardcoded Google API key

**Severity:** high

A Google API key appears to be hardcoded.

- **Why it matters:** A committed Google API key can be abused to run up billing or access enabled services on your project.
- **How to fix:** Restrict, rotate, and move the key out of source into environment config.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `SECRET_LLM_API_KEY` — Hardcoded AI/LLM API key

**Severity:** high

An OpenAI/Anthropic-style API key appears to be hardcoded.

- **Why it matters:** A leaked LLM API key lets anyone spend against your account and access your usage. These keys are actively scraped from public repos.
- **How to fix:** Revoke and rotate the key; read it from the environment, never commit it.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `SECRET_SLACK_TOKEN` — Hardcoded Slack token

**Severity:** high

A Slack token appears to be hardcoded.

- **Why it matters:** A Slack token can read messages, post as your app, and access workspace data until it is revoked.
- **How to fix:** Revoke and rotate the token; load it from the environment.
- **Reference:** https://cwe.mitre.org/data/definitions/798.html

### `SECRET_PRIVATE_KEY_URL_CREDS` — Credentials embedded in a URL

**Severity:** medium

A URL contains an inline username:password.

- **Why it matters:** Credentials in a URL leak through logs, browser history, referrer headers, and process listings.
- **How to fix:** Move credentials out of the URL and pass them via a secure config channel.
- **Reference:** https://cwe.mitre.org/data/definitions/598.html

