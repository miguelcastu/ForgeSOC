# ADR-006: Validate external records and make rejection policy explicit

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

External telemetry may contain malformed JSON, missing fields, invalid IPs,
unsupported events, or unknown sources. Silently dropping those records hides
data-quality and security visibility problems, while stopping every production
stream may also be undesirable.

## Decision

Use Pydantic v2 for the untrusted raw envelope and provider payloads while
retaining dataclasses for internal domain models. Default to strict processing.
Offer an explicit continue-on-error mode that requires a rejection file. Store
error context and classification but not raw payloads in that file.

## Alternatives considered

- Manual validation only: avoids a dependency but repeats parsing and produces
  less structured errors.
- Convert the complete domain to Pydantic: blurs external validation and domain
  responsibilities.
- Always skip invalid events: risks invisible data loss.
- Always stop: unsuitable for later long-running ingestion.

## Consequences

Validation failures are explainable and measurable. Pydantic becomes a runtime
dependency. Rejection metadata is safer by default, but operators needing raw
failed payloads must retrieve them from the controlled source system.
