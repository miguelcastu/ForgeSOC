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

## Current non-goals

- A complete SIEM replacement
- Endpoint agent or packet capture
- Production telemetry ingestion
- Database, web API, or message broker
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
