# ADR-013: Local authentication and role-based workflow

## Status

Accepted in Sprint 6.

## Context

The Sprint 5 console could mutate telemetry and run detections without knowing
who initiated an action. Alert ownership, notes, cases, and accountability all
require a stable operator identity.

## Decision

ForgeSOC stores local users in PostgreSQL, hashes passwords with salted
PBKDF2-SHA256, and issues HMAC-signed eight-hour bearer sessions. Roles are
`admin`, `analyst`, and `viewer`. The first administrator is created through a
one-time bootstrap endpoint that closes once any user exists. Important
mutations are written to an append-only audit table.

## Consequences

- The local workshop remains self-contained and needs no external identity
  provider.
- A strong session secret is required and rotating it logs everyone out.
- Local auth is understandable and testable, but it is not a substitute for
  enterprise SSO, MFA, TLS, recovery flows, or centralized policy.
