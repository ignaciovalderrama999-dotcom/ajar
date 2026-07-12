# Acceptable Use Policy

ajar is built for one purpose: **helping people find and fix weaknesses in their
own software.** Analyze and protect — never attack.

## You MAY use ajar to

- ✅ Scan source code that **you own**.
- ✅ Scan source code you have **written, explicit authorization** to review
  (e.g. an employer's repo, a client engagement with a signed agreement, an
  open-source project you contribute to).
- ✅ Audit **the local machine you are running it on** (`ajar host`) — its own
  listening ports and firewall — when it is **your** machine or one you are
  authorized to administer.
- ✅ Learn about security by reading its findings and references.
- ✅ Integrate it into your own CI/CD pipeline or development workflow.

## You MAY NOT use ajar to

- ❌ Analyze or target systems, code, or machines you do **not** own and are
  **not** authorized to assess.
- ❌ Scan, probe, or port-scan any host other than the local machine you run it
  on. `ajar host` inspects **only the local machine's own state** and must not
  be modified to reach other hosts.
- ❌ Support, plan, or carry out any unauthorized, unlawful, or malicious act.
- ❌ Represent a clean scan as a formal security guarantee or certification.

## What ajar deliberately does NOT do

- It does **not** attack, exploit, or generate exploit code, payloads, or
  offensive tooling.
- It does **not** connect to, probe, or port-scan any remote system. Code
  scanning reads local files only; `ajar host` only reads the local machine's
  own listening sockets and firewall state (it never opens a connection).
- It does **not** collect telemetry or transmit your code anywhere.

By using ajar you agree to use it only in ways consistent with this policy and
with all laws that apply to you. Misuse is your responsibility, not the author's.
See the [DISCLAIMER](DISCLAIMER.md) for the full limitation of liability.
