# Security Policy

passkey-tpm protects authentication credentials. We take vulnerability reports seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub Security Advisories](https://github.com/dangerousplay/passkey-tpm/security/advisories/new).

Include affected version/commit, impact, and reproduction steps. We aim to acknowledge
reports within 72 hours and to publish a fix and advisory within 90 days.

## Supported versions

passkey-tpm is pre-alpha. Only the `main` branch receives security fixes until the first release.

## Scope

The threat model is in [docs/threat-model.md](docs/threat-model.md). Physical attacks on the
TPM (fault injection, bus interposers) and a compromised kernel or root account are out of scope.
