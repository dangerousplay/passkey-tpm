# ADR 0002: Standalone provider with uhid and D-Bus front-ends

- Status: Accepted
- Date: 2026-10-03

## Context

Browsers, libfido2, pam_u2f and systemd-cryptenroll talk to FIDO HID devices today.
credentialsd (Credentials for Linux) is building a portal-based architecture with TPM platform
authenticators on its roadmap, but has no provider API yet (credentialsd #8, #26).

## Decision

One authenticator implementation with two front-ends:

1. A virtual CTAPHID device via `/dev/uhid`, which works with existing clients now.
2. A provider D-Bus interface co-designed with linux-credentials for the portal path.

## Consequences

- The core API is transport-agnostic.
- uhid cannot reach Flatpak/Snap-confined apps without extra interfaces, and Chromium ignores
  uhid authenticators that claim to be platform authenticators; the portal path addresses both.
