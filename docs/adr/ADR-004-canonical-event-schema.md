# ADR-004: Use a versioned canonical event schema inspired by OCSF

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

Windows and Linux represent equivalent authentication activity with different
field names, values, and timestamp formats. Detectors should not contain a
separate branch for every telemetry provider. OCSF offers a useful industry
reference, but implementing its complete schema would exceed current needs.

## Decision

Normalize supported source records into the small ForgeSOC `SecurityEvent`
model. Add `schema_version`, currently `1.0.0`, plus source provenance and stable
source record identity. Use OCSF concepts as a reference without claiming full
OCSF compliance. Derive normalized event IDs deterministically from
`source_type` and `source_record_id`.

## Alternatives considered

- Keep provider-native records throughout detection: couples every rule to
  every source.
- Implement all of OCSF immediately: comprehensive but disproportionate and
  difficult to validate at this stage.
- Use an unversioned custom schema: simpler initially but unsafe to evolve.

## Consequences

Detectors consume one vocabulary and repeated normalization is stable. Every new
source requires maintained mappings. Schema changes must consider compatibility
and increment the version when their meaning changes.
