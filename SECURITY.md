# Security Policy

## Scope

ajar is a local static-analysis CLI. It reads files on the machine it runs on
and does not connect to any network service. It collects no telemetry.

## Reporting a vulnerability in ajar itself

If you find a security issue **in ajar's own code** (for example, a way a
crafted input file could crash or misbehave), please report it privately:

- Open a [GitHub Security Advisory](https://github.com/ignaciovalderrama999-dotcom/ajar/security/advisories/new), or
- Email the maintainer (add your contact here).

Please do **not** open a public issue for a security vulnerability until it has
been addressed.

## Out of scope

ajar does not execute the code it scans and does not act on remote systems.
Reports about using ajar to attack third-party systems are out of scope and
contrary to its [Acceptable Use Policy](ACCEPTABLE_USE.md) — ajar is a defensive
tool only.
