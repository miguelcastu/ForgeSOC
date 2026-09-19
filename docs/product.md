# Product scope

## Intended users

- SOC analysts
- Detection engineers
- Detection platform engineers
- Security software engineers
- SOC platform engineers

## Problem statement

Security telemetry arrives in different formats and at different levels of
quality. Detection teams need a reliable path from raw events to explainable,
testable findings without coupling every rule directly to one data source or
storage technology.

ForgeSOC is an educational Open Detection & Response Platform for exploring
that path progressively. The long-term direction includes normalization,
detection, enrichment, correlation, risk, incidents, and controlled response,
but each capability must be justified by an observed problem before it is
introduced.

## Implemented in Sprint 1

- Streaming ingestion of synthetic JSONL authentication events.
- Typed event and alert domain models.
- A detector contract and orchestration engine.
- Stateful brute-force detection with a sliding time window.
- Alert suppression and successful-login reset behavior.
- JSONL alert output and a command-line interface.
- Unit and end-to-end tests.

## Implemented in Sprint 2

- Deterministic synthetic telemetry controlled by a seed and start time.
- Authentication, process, network, DNS, and HTTP event generation.
- Normal, brute-force, post-compromise, suspicious PowerShell, malicious-domain,
  and credential-spraying scenarios.
- A protected JSONL writer and dedicated generator CLI.
- Replay of generated authentication scenarios through the detection engine.

## Implemented in Sprint 3

- A versioned canonical event schema inspired by OCSF concepts.
- Raw JSONL envelopes with source provenance and source record identity.
- Pydantic validation at external boundaries.
- Windows Security and Linux SSH authentication adapters.
- Deterministic normalized event IDs.
- Strict and continue-on-error policies with explicit rejection output.
- Data-quality counts by source, event type, and error code.
- A raw-to-normalized-to-alert command-line pipeline.

## Implemented in Sprint 4

- PostgreSQL storage for canonical events, alerts, and ordered alert evidence.
- SQLAlchemy repositories separated from the domain and detection layers.
- Alembic migrations with forward, reverse, and schema-drift checks in CI.
- Idempotent event ingestion using event identity and source-record identity.
- Transactional database-backed detection over explicit UTC time ranges.
- A database CLI for health checks, ingestion, detection, and basic statistics.
- Docker Compose development infrastructure and isolated PostgreSQL tests.

## Implemented in Sprint 5

- A responsive analyst console served directly by ForgeSOC.
- Dashboard metrics and visual event/severity distributions.
- Filtered, cursor-paginated event and alert exploration.
- Alert investigation with ordered evidence.
- Browser-based canonical/raw JSONL import and synthetic scenario generation.
- Browser-triggered detection with idempotent results.
- Versioned FastAPI endpoints, OpenAPI, health checks, and request IDs.
- An embedded HTML architecture guide and five-minute workshop script.
- A containerized API service and complete PostgreSQL API tests.

## Current non-goals

- A complete SIEM replacement
- Endpoint agent or packet capture
- Production telemetry ingestion
- Message broker or streaming ingestion
- Internet-facing multi-user deployment
- Authentication and role-based access control
- Machine-learning detection
- Autonomous remediation
- User interface

## Engineering principles

1. Correctness before extensibility.
2. Simplicity before infrastructure.
3. Explicit, testable boundaries.
4. Synthetic data only in the repository.
5. Documentation evolves with the code.
6. New technology must solve a demonstrated limitation.
