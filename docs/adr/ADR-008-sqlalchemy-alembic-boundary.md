# ADR-008: Isolate SQLAlchemy and version the schema with Alembic

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

Persistence must not make detection rules depend on ORM state. The project also
needs repeatable schema creation and reviewable evolution rather than tables
created implicitly at application startup.

## Decision

Use synchronous SQLAlchemy 2 with psycopg 3 because the current application is
synchronous and bounded. Keep ORM rows, mappers, repositories, and services in
`forgesoc.persistence`; domain models remain frozen dataclasses with no
SQLAlchemy imports.

Use Alembic for every schema change. CI applies migrations, checks model/schema
drift, downgrades to the empty schema, and upgrades again. Application code
never calls `metadata.create_all()`.

## Alternatives considered

- Async SQLAlchemy: adds event-loop and driver complexity without concurrent
  ingestion requirements in this sprint.
- ORM entities as domain models: fewer types initially, but persistence state
  would leak into detection and tests.
- Handwritten SQL only: valid, but loses typed mappings and Alembic comparison
  against declared metadata.
- Automatic table creation: easy locally, but provides no production-safe
  schema history or reviewed upgrade path.

## Consequences

Persistence can evolve without rewriting detection contracts and unit tests can
exercise mappings without a running service. Mapping code is explicit work and
must be tested in both directions. Schema declarations and migrations must stay
aligned, which CI verifies.
