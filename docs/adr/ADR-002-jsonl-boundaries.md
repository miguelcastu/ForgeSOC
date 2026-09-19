# ADR-002: Use JSONL for initial event and alert boundaries

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

Sprint 1 needs a transparent, streamable input and output format before a
database or message broker has been justified.

## Decision

Represent each security event and alert as one JSON object per line. Convert
input records to typed domain objects at ingestion and domain alerts back to
JSON only at output.

## Alternatives considered

- One JSON array: easy to inspect but encourages loading the complete document.
- CSV: compact but awkward for optional and nested evidence fields.
- PostgreSQL or Kafka: useful later, but premature infrastructure for the first
  synchronous pipeline.

## Consequences

Datasets remain human-readable and can be processed incrementally. JSONL does
not provide schema enforcement, transactions, indexing, or concurrency control;
those limitations are accepted for Sprint 1.
