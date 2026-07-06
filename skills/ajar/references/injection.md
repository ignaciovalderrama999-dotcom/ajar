# Injection vulnerabilities — find, verify, fix

For each class: where it hides, how to confirm it's real, the attacker's angle
(so you understand impact — never to weaponize), and the *correct* fix.

---

## SQL injection

**Where:** any query built with string concatenation, f-strings, `.format()`, or
template literals where part of the string is user input. Also ORMs used in
"raw" mode (`.raw()`, `.extra()`, `text()`).

**Verify:** trace the interpolated value to a request source. If it's an integer
that's cast (`int(uid)`) or a parameterized placeholder, it's safe.

**Impact:** read/modify any data, dump the whole DB, sometimes RCE via the DB.

**Fix — parameterize (the value is data, never SQL):**
```python
# BAD
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
# GOOD
cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
```
```js
// BAD:  db.query(`SELECT * FROM u WHERE id = ${id}`)
// GOOD: db.query("SELECT * FROM u WHERE id = $1", [id])
```
Column/table names can't be parameterized — allow-list them against a fixed set.
Never "escape manually" — use the driver's parameter binding.

---

## Command injection

**Where:** `os.system`, `subprocess(..., shell=True)`, `exec`, backticks,
`child_process.exec` — with any user input in the command string.

**Verify:** is user input concatenated into the command? `shell=True` + a
built string = injectable via `; | && $(...)`.

**Fix — no shell, pass an argument list:**
```python
# BAD
os.system("ping -c 1 " + host)
subprocess.run(cmd, shell=True)
# GOOD
subprocess.run(["ping", "-c", "1", host], shell=False)
```
Validate `host` against an allow-list/regex if it must be dynamic. Avoid `exec`/
`eval` entirely; use `ast.literal_eval` for data or a dispatch dict for behavior.

---

## Cross-site scripting (XSS)

**Where:** `innerHTML`/`outerHTML =`, `document.write`, `dangerouslySetInnerHTML`,
`v-html`, template engines with autoescape off (`| safe`, `mark_safe`,
`{% autoescape off %}`), and `javascript:` URLs.

**Verify:** does user-influenced data reach the HTML sink unescaped? A value
rendered as React `{value}` or a Jinja `{{ value }}` with autoescape ON is safe.

**Impact:** run script in the victim's browser → steal sessions/tokens, act as
the user, keylog, deface.

**Fix — render as text, or sanitize:**
```jsx
// BAD:  <div dangerouslySetInnerHTML={{__html: userHtml}} />
// GOOD (text): <div>{userText}</div>
// GOOD (must be HTML): sanitize first
import DOMPurify from "dompurify";
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userHtml)}} />
```
Keep template autoescaping ON. Add a Content-Security-Policy as defense in depth.

---

## SSRF (server-side request forgery)

**Where:** `fetch`/`axios`/`requests`/`urlopen` where the URL comes from the
request. Common in "fetch this URL", webhooks, image proxies, PDF/screenshot
generators.

**Verify:** can the user control the host? Then they can hit `http://localhost`,
`http://169.254.169.254/` (cloud metadata), and internal services.

**Fix — allow-list + block private ranges:**
- Accept only `https` and hosts on a fixed allow-list, OR
- Resolve the hostname and reject if it maps to a private/loopback/link-local IP
  (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1). Re-check after
  redirects and disable auto-redirects for these calls.

---

## Path traversal

**Where:** `open(...)`, `sendFile`, `fs.readFile`, static handlers where the path
comes from the request. `../../etc/passwd` escapes the intended directory.

**Fix — resolve and confine:**
```python
base = Path("/srv/uploads").resolve()
target = (base / user_path).resolve()
if not target.is_relative_to(base):   # py311+, else check str.startswith
    raise PermissionError
```
Reject any input containing path separators or `..` when a bare filename is
expected.

---

## Insecure deserialization

**Where:** `pickle.loads`, `yaml.load` (without `SafeLoader`), Java
`ObjectInputStream`, PHP `unserialize`, `marshal` — on untrusted data.

**Impact:** typically remote code execution.

**Fix:** never deserialize untrusted input with a code-capable format. Use JSON
for data interchange; `yaml.safe_load`; validate with a schema (pydantic).

---

## Server-side template injection (SSTI)

**Where:** user input concatenated into a template *string* then rendered
(`render_template_string`, building a Jinja/Handlebars template from input).

**Impact:** template expression evaluation → often RCE.

**Fix:** render from static template files; pass user data only as escaped
*variables*, never as part of the template body.

---

## The cross-line trap (why data-flow matters)

The dangerous line often looks innocent because the tainting happened earlier:
```python
uid = request.args.get("id")      # source
q = build_query(uid)              # taint carried into q
cursor.execute(q)                 # sink looks clean, but q is tainted
```
When verifying, **follow the variable back to its origin**, don't judge the sink
line in isolation. (ajar's taint pass flags these, but confirm the flow yourself.)
