# Security Policy

## Scope

ajar is a local, defensive analysis CLI. It runs entirely on the machine it is
invoked on and **never opens a network connection to scan anything**:

- **Code analysis** (`ajar scan`) reads local source files only.
- **Host audit** (`ajar host`) reads only the **local machine's own** listening
  sockets and firewall state (via the OS) — it never connects to a port, never
  scans another machine, and never changes anything.

It collects no telemetry and transmits nothing anywhere.

## Reporting a vulnerability in ajar itself

If you find a security issue **in ajar's own code** (for example, a way a
crafted input file could crash or misbehave), please report it privately:

- Open a [GitHub Security Advisory](https://github.com/ignaciovalderrama999-dotcom/ajar/security/advisories/new), or
- Email the maintainer (add your contact here).

Please do **not** open a public issue for a security vulnerability until it has
been addressed.

## Out of scope

ajar does not execute the code it scans and does not act on remote systems. The
host audit is hard-wired to the local machine (it accepts no target host and
cannot be pointed at another system without rewriting the source). Reports or
requests about using ajar to scan, probe, or attack third-party systems are out
of scope and contrary to its [Acceptable Use Policy](ACCEPTABLE_USE.md) — ajar
is a **defensive, local-only** tool.
