# ADR-005: Use source-specific normalization adapters

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

Each telemetry source uses different validation and mapping rules. A single
normalization function with provider conditionals would grow difficult to test
and change safely.

## Decision

Define a structural `Normalizer` protocol. Each source implements one adapter
identified by `source_type`. `NormalizationEngine` owns a registry, selects the
adapter, and remains unaware of provider field names.

## Alternatives considered

- One function containing `if source == ...`: initially short but increasingly
  coupled.
- Teach detections every source format: duplicates mappings across rules.
- Configuration-only mappings: attractive for simple renames but premature for
  validation, value conversion, and source-specific semantics.

## Consequences

Sources can be tested and added independently. The project contains more small
modules, and duplicate source registrations must be rejected explicitly.
