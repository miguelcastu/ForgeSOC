# ADR-007: Use PostgreSQL for durable telemetry and alert storage

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

JSONL is useful for fixtures and exchange, but it cannot enforce concurrent
identity, relational evidence integrity, transactional writes, or efficient
time-range queries. Sprint 3 established stable canonical event IDs, making
durable deduplication practical.

## Decision

Use PostgreSQL as ForgeSOC's first operational datastore. Keep JSONL as an
ingestion and output boundary. Represent IP addresses with `INET`, flexible
event details with `JSONB`, temporal values with timezone-aware timestamps, and
alert evidence with a relational join table.

Use PostgreSQL 17 in local Compose and CI. This version is infrastructure
configuration, not a promise that application SQL requires version 17.

## Alternatives considered

- Continue using JSONL: smallest stack, but no transactional or indexed shared
  state.
- SQLite: simple local setup, but it would not validate the PostgreSQL types and
  conflict semantics intended for the project.
- Document database: natural for varied payloads, but weaker for ordered alert
  evidence and the relational queries currently needed.

## Consequences

ForgeSOC gains durable replay, integrity constraints, and realistic query
behavior. Developers and CI need a PostgreSQL service for full integration
coverage. Database operations are PostgreSQL-specific by design, so pretending
they are portable to every SQL engine is not a goal.
