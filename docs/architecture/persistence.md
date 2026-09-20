# PostgreSQL persistence architecture

## Purpose

Sprint 4 makes normalized telemetry durable and replayable. It stores canonical
events independently from source formats, runs the existing detection engine
over an explicit time range, and preserves the evidence behind every alert.

## Boundaries

```text
CLI -> application service -> repository -> SQLAlchemy session -> PostgreSQL
             |                    |
             |                    +-> ORM rows
             +-> domain events and alerts
```

The domain and detection packages do not import SQLAlchemy. ORM rows describe
storage, mappers translate them, repositories implement database operations,
and services own transactions. This keeps a schema migration from becoming a
domain-model redesign.

## Relational model

### `events`

Stores canonical `SecurityEvent` values. `event_id` is the primary identity and
`(source, source_record_id)` is a second unique identity when the provider has
one. PostgreSQL `INET` validates IP values, `JSONB` preserves event-specific
attributes, and timezone-aware timestamps retain a single temporal meaning.

### `alerts`

Stores stable UUID alert identities and the human-readable detection result.
Alert IDs are derived from the rule and ordered evidence IDs, so replaying the
same event window produces the same alert rather than an extra row.

### `alert_events`

Links alerts to their source events. The composite primary key prevents the
same event from being attached twice and `evidence_order` preserves the exact
sequence used by the detector. An alert is rejected when any referenced event
is absent.

## Idempotency and transactions

Event inserts use PostgreSQL `ON CONFLICT DO NOTHING`. Replaying a file is
therefore measurable as duplicates, not a fatal error. Alert insertion follows
the same rule using its deterministic UUID.

Repositories deliberately do not call `commit()`. `EventIngestionService` and
`DatabaseDetectionService` each open one transaction for the complete use case.
An exception rolls the whole operation back, including alert evidence.

## Queries and indexes

Detection reads a half-open interval: `start <= timestamp < end`, ordered by
`(timestamp, event_id)` for deterministic stateful processing. Indexes support
time-range scans and likely future filters by event type, username, source IP,
rule, and severity.

Use PostgreSQL to verify real plans as datasets grow:

```sql
EXPLAIN (ANALYZE, BUFFERS)
SELECT *
FROM events
WHERE timestamp >= TIMESTAMPTZ '2026-09-19T00:00:00Z'
  AND timestamp < TIMESTAMPTZ '2026-09-20T00:00:00Z'
ORDER BY timestamp, event_id;
```

Do not optimize from the existence of an index alone. Review the measured plan,
row count, and buffer usage with representative synthetic volume first.

## Configuration and migrations

`FORGESOC_DATABASE_URL` is required and must use the
`postgresql+psycopg://` driver. Alembic is the only supported way to create or
change the schema. CI upgrades, checks for model drift, downgrades to the empty
schema, and upgrades again before running tests.

## Current limitations

- Detection loads at most 100,000 events for one time range into memory.
- Processing is synchronous and single-process.
- There is no checkpoint, scheduler, late-event policy, retention policy, or
  partitioning strategy yet.
- The database CLI composes the same typed detector registry as the API and
  file pipeline, keeping enabled rules consistent across execution paths.
- Database credentials and production operations remain deployment concerns;
  the Compose service is development-only.

These limits are visible design inputs for later ingestion and orchestration
sprints rather than hidden production guarantees.
