# Reporting a vulnerability

This is a small, single-maintainer project, but security reports are taken
seriously and answered.

- **Do not open a public issue for a vulnerability.**
- Use GitHub's private channel: **Security → Advisories → Report a vulnerability**
  on this repository. That opens a draft advisory only you and the maintainer can
  see.
- If that is unavailable, open an issue with no details and ask for a private
  channel.

What to expect:

| Step | Target |
| --- | --- |
| Acknowledged | within 72 hours |
| Assessment (affected versions, severity) | within 7 days |
| Fix or mitigation | as fast as the severity warrants; you get the patch before the announcement |

Please include: affected version or commit, a minimal reproducer, the platform,
and what an attacker gains. If the issue is in a dependency rather than in this
code, say so — it still helps.

## Scope

In scope: anything that lets a caller recover a secret, bypass a check this
library documents, or write/modify data outside what the API promises.

Out of scope: issues that require an attacker who already runs code as the same
Windows user (DPAPI and file permissions are not a boundary against that), and
denial of service on a service you control the machine for.

## No bug bounty

There is no money behind this, only gratitude and a credit line in the advisory
unless you prefer to stay anonymous.