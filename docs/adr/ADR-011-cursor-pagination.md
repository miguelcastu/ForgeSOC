# ADR-011: Use opaque keyset cursors for API pagination

- **Status:** Accepted
- **Date:** 2026-09-20

## Context

Telemetry may be inserted while an analyst moves through results. Offset pages
can skip or repeat records after such inserts and become slower at large
offsets. Stateful ordering also requires deterministic tie-breaking.

## Decision

Sort event queries by descending `(timestamp, event_id)` and alert queries by
descending `(timestamp, alert_id)`. Encode the last pair in an opaque URL-safe
cursor and request records strictly following it. Limit public pages to at most
200 items.

## Alternatives considered

- Offset and limit: easier to expose page numbers, but unstable under inserts.
- Database-generated cursor state: strong control, but requires server-side
  lifecycle and storage for a simple read API.
- Timestamp only: ambiguous when multiple records have the same timestamp.

## Consequences

Forward navigation is deterministic and index-friendly. The browser keeps a
local cursor stack to support Previous. Cursors are transport tokens rather
than permanent identifiers and clients must not interpret their contents.
