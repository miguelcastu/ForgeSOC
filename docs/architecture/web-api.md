# Web console and API architecture

## Purpose

Sprint 5 turns the durable Sprint 4 pipeline into an analyst-facing product.
The same process serves a versioned HTTP API and a responsive browser console,
making events, findings, and evidence accessible without SQL or routine CLI
use.

## Runtime flow

```text
browser
  |
  +-- static HTML/CSS/JavaScript
  |
  +-- /api/v1/* -> FastAPI validation -> repositories -> PostgreSQL
                         |
                         +-> domain models -> response schemas
```

Static assets contain no secrets and make calls only to the same origin. There
is no external CDN, JavaScript package runtime, or frontend build requirement.
FastAPI generates OpenAPI from the response and request schemas.

## Endpoint groups

| Group | Purpose |
| --- | --- |
| `/health/*` | Process liveness and PostgreSQL readiness. |
| `/api/v1/events` | Filter, page, import, and inspect canonical events. |
| `/api/v1/raw/import` | Normalize and ingest Windows/Linux raw envelopes. |
| `/api/v1/alerts` | Filter findings and retrieve ordered evidence. |
| `/api/v1/stats` | Aggregate sources, event types, rules, and severities. |
| `/api/v1/scenarios` | Discover deterministic synthetic datasets. |
| `/api/v1/demo/seed` | Generate and ingest a selected safe scenario. |
| `/api/v1/detections/run` | Replay a bounded range through current rules. |
| `/api/docs` | Interactive OpenAPI documentation. |

## Pagination

Event pages are sorted by descending `(timestamp, event_id)` and alerts by
descending `(timestamp, alert_id)`. An opaque URL-safe cursor contains the last
pair seen. The next query requests rows strictly after that position in the
sort order. This avoids the duplicates and skipped rows that offset pagination
can produce when telemetry is inserted between requests.

The public limit is capped at 200 records. The browser uses smaller pages to
keep interaction fast.

## Browser functionality

- Overview metrics, event-type bars, severity distribution, and latest alerts.
- Event filters by type, source, username, source IP, and outcome.
- Alert filters by severity, rule, username, and source IP.
- Detail drawers for canonical attributes and ordered alert evidence.
- Canonical and raw Windows/Linux JSONL import with validation and a
  5,000-record request limit.
- Deterministic scenario generation and idempotent detection execution.
- Embedded architecture diagram, glossary, principles, and workshop script.

## Error and observability contract

Errors return a stable code, safe message, and request ID. Every response also
contains `X-Request-ID` and `X-Response-Time-Ms`. Database failures do not
expose connection URLs, SQL, or credentials.

## Security boundary

This sprint is a local educational console, not an internet-facing service.
There is no authentication or authorization. The launcher binds to localhost
and the Compose port is intended only for a trusted development machine.

Before any shared deployment, add authentication, roles, TLS termination,
CSRF/origin policy for mutations, rate limiting, and audited operator actions.

## Intentional limitations

- API operations are synchronous.
- The only active detection rule remains authentication brute force.
- Raw import supports the current structured Windows and Linux adapters, not
  native EVTX or unstructured syslog files.
- There is no alert assignment, status, comments, or case management yet.
- Demo event identities are deterministic, so repeating a scenario reports
  duplicates rather than creating another run.
