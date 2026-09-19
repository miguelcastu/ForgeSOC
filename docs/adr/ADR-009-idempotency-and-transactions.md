# ADR-009: Make replay idempotent and let services own transactions

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

Security pipelines routinely retry files and time windows. Treating retries as
new data creates duplicate telemetry and repeated alerts. Committing individual
repository calls can also leave alerts without complete evidence after a
failure.

## Decision

Deduplicate events by canonical `event_id` and by `(source, source_record_id)`.
Use deterministic UUIDv5 alert IDs derived from the rule and ordered evidence
IDs. PostgreSQL inserts use `ON CONFLICT DO NOTHING` and services report the
number of inserted and duplicate records.

Repositories flush work into a caller-provided session but never commit.
Application services establish one transaction around ingestion or detection,
including every alert-evidence link. Foreign keys reject missing evidence.

## Alternatives considered

- Random alert UUIDs: simple, but identical replay creates another alert.
- Check-then-insert only: races under concurrent writers.
- Commit in each repository method: convenient in isolation, but prevents a use
  case from rolling back atomically.
- Silently omit missing evidence: preserves an alert row while destroying its
  explainability.

## Consequences

Retries are safe and observable, transaction failures do not leave partial use
cases, and every persisted alert remains explainable. Changing the evidence set
intentionally changes alert identity. Concurrent processing and checkpointing
still need a later design; this decision only establishes storage semantics.
