# ADR-003: Generate deterministic synthetic telemetry

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

ForgeSOC needs realistic enough security datasets for repeatable detection tests,
demos, and future regression suites. Real telemetry would introduce privacy and
security risks, while uncontrolled random data would make failures difficult to
reproduce.

## Decision

Generate synthetic canonical events from named scenarios. A local
`random.Random` instance receives an explicit seed, the clock starts from an
explicit timezone-aware timestamp, and event IDs derive from scenario name plus
sequence number. Use fictional identities, reserved IP ranges, and reserved
domains. Do not add Faker or external data services.

## Alternatives considered

- Static fixture files only: simple, but harder to vary and maintain across many
  related scenarios.
- Global `random` and UUID4: convenient, but outputs differ between runs.
- Faker: broad data generation, but adds a dependency and version-dependent
  behavior that is unnecessary for the current controlled vocabulary.
- Real or captured logs: more realistic, but unsafe for a public repository and
  difficult to reproduce.

## Consequences

Scenario inputs can be reproduced exactly and safely committed or regenerated.
The generator is intentionally not a performance/load generator. Vendor-specific
source variation will require a later normalization-focused design.
