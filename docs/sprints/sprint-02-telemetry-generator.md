# Sprint 2: deterministic telemetry generator

## Goal

Create controlled, reproducible security telemetry for testing detections and
demonstrating both positive and negative scenarios without using real data.

## Delivered capabilities

- Six event kinds: authentication success/failure, process start, network
  connection, DNS query, and HTTP request.
- Six named scenarios covering normal activity and suspicious behavior.
- Seeded choices, deterministic event IDs, and a simulated clock.
- Safe fictional entities and reserved documentation infrastructure.
- JSONL serialization with overwrite protection.
- Scenario discovery and generation through `forgesoc-generate`.
- End-to-end replay through the Sprint 1 detector.

## Data flow

```text
Scenario
   |
   v
TelemetryGenerator
   |
   v
SecurityEvent stream
   |
   +--> JSONL dataset
   |
   +--> DetectionEngine --> alerts
```

## Acceptance criteria

| Requirement | Evidence |
| --- | --- |
| Same inputs produce the same events | Determinism test |
| IDs are unique and timestamps ordered | Contract test for every scenario |
| All six event kinds are represented | Event coverage test |
| Brute force creates one alert | Scenario replay test |
| Normal activity creates no alert | Negative replay test |
| Credential spraying creates no current brute-force alert | Negative replay test |
| DNS/network/HTTP chain remains correlated | Correlation ID test |
| Existing files are not silently replaced | Writer protection test |
| Generated JSONL can be ingested | Round-trip test |

## Commands

```powershell
uv run forgesoc-generate --list-scenarios

uv run forgesoc-generate `
  --scenario malicious-domain `
  --seed 42 `
  --start-time 2026-01-01T09:00:00+00:00 `
  --output data/generated/malicious-domain.jsonl
```

To regenerate an intentionally disposable output:

```powershell
uv run forgesoc-generate `
  --scenario malicious-domain `
  --output data/generated/malicious-domain.jsonl `
  --force
```

## Concepts introduced

- A second structural `Protocol`, this time for interchangeable scenarios.
- Dependency injection by passing a configured generator into each scenario.
- Seeded pseudo-randomness versus uncontrolled randomness.
- A simulated clock for repeatable temporal behavior.
- Event factories that centralize IDs, timestamps, and common fields.
- Positive and negative detection datasets.
- Correlation identifiers for related events.
- Safe file handling through explicit overwrite permission.

## Intentional limitations

- Events are canonical ForgeSOC events, not vendor-specific raw logs.
- Scenario sizes are fixed and designed for correctness, not load testing.
- Only brute-force detection exists, so the other suspicious scenarios are
  datasets for future rules.
- `attributes` provides flexible type-specific data but is not yet validated by
  per-event schemas.
- This remains synchronous because the workload does not justify concurrency.

These limitations identify future problems without implementing normalization,
Pydantic, Kafka, storage, or async processing prematurely.
