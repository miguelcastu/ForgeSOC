# ADR-012: Version the API and keep Sprint 5 local and unauthenticated

- **Status:** Accepted
- **Date:** 2026-09-20

## Context

The web console needs read and demonstration operations, but ForgeSOC does not
yet have user identity, roles, secrets management, TLS, or audited operator
actions. Pretending the service is production-ready would create an unsafe
default.

## Decision

Place product endpoints under `/api/v1`, return explicit response schemas, and
use stable structured errors with request IDs. Bind the direct server to
`127.0.0.1` by default. Treat scenario generation, canonical import, and
detection execution as trusted local workshop operations.

Do not implement permissive CORS or claim public deployment support. Document
authentication and authorization as prerequisites for shared deployment.

## Alternatives considered

- Add authentication in this sprint: materially expands scope into identity,
  credential lifecycle, roles, sessions, and threat modeling.
- Expose unversioned endpoints: smaller paths, but no safe compatibility
  boundary for future clients.
- Enable all origins: convenient during development, but unsafe for mutation
  endpoints and unnecessary for a same-origin console.

## Consequences

The local workshop is easy to run while security limitations remain explicit.
Future multi-user operation requires a separate decision and cannot be achieved
by simply binding the current server to a public interface.
