# Disclaimer & Limitation of Liability

**Please read this before using ajar.**

## No warranty

ajar is provided **"AS IS", without warranty of any kind**, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose, and non-infringement, as stated in the [LICENSE](LICENSE)
(Apache License 2.0, Sections 7 and 8). You use it entirely at your own risk.

## Not a security guarantee

ajar is a **best-effort static analysis aid**, not a certification, audit, or
guarantee of security. Specifically:

- **A clean scan does not mean your code is secure.** ajar can miss real
  vulnerabilities (false negatives). It uses heuristic pattern matching and does
  not understand full program behavior.
- **ajar may report issues that are not exploitable** in your context (false
  positives). Every finding requires human judgement.
- Passing ajar is **not** evidence of compliance with any security standard,
  regulation, or contractual obligation.

You remain solely responsible for the security of your own software.

## Intended and authorized use only

ajar is a **defensive** tool. It is intended to be run **only** on:

1. source code that **you own**, or
2. source code that you have **explicit, documented authorization** to analyze.

ajar analyzes local files and **does not attack, exploit, probe, or interact
with any remote system**. It must not be used as part of any unauthorized,
unlawful, or malicious activity. Using this software in violation of any
applicable law is strictly outside its intended purpose.

## Your responsibility, not the author's

The author and contributors of ajar:

- do **not** control how third parties obtain, modify, or use this software;
- are **not responsible** for the actions of anyone who uses, forks, or
  redistributes it, including any use that combines ajar with other tools
  (AI assistants, automation, or otherwise);
- are **not liable** for any direct, indirect, incidental, special, or
  consequential damages arising from the use or misuse of this software.

**If you use this software, you accept full responsibility for how you use it
and for complying with all laws that apply to you.** If you do not agree, do not
use ajar.

## Modified versions and forks

This software is open source, so anyone may copy or modify it. **If someone
forks ajar and changes it — including adding malicious, harmful, or unlawful
code — that modified version is entirely their responsibility, not the
author's.**

- The author endorses **only** the official version published at the canonical
  repository. Any fork, mirror, or modified copy is **not** endorsed and is
  **not** the author's work.
- The public commit history of the official repository is the record of what
  the original author actually wrote. Changes made by others are attributable to
  them, not to the author.
- The name **"ajar"** and the author's name may **not** be used to promote,
  endorse, or lend credibility to any modified or derivative version without the
  author's written permission.

If you obtained a build of "ajar" from anywhere other than the official
repository, treat it as untrusted until you have verified it.

## Limitation of liability

To the maximum extent permitted by applicable law, in no event shall the author
or contributors be liable for any claim, damages, or other liability, whether in
an action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or its use.

---

_This document is not legal advice. If you need certainty for a specific
jurisdiction or commercial use, consult a qualified lawyer in your country._
