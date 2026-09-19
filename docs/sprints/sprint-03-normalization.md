# Sprint 3: authentication normalization

## Goal

Convert synthetic Windows Security and Linux SSH authentication records into a
single versioned event model that the existing detection engine can process
without provider-specific logic.

## Delivered capabilities

- Raw JSONL envelopes with file and line provenance.
- Pydantic validation of envelopes, Windows payloads, Linux payloads, IPs, and
  timezone-aware timestamps.
- Windows Event IDs 4624 and 4625.
- Structured Linux `sshd` accepted/failed results.
- UTC timestamps and deterministic event identity.
- A registry-driven normalization engine.
- Explicit success/failure result types and stable error codes.
- Strict and continue-on-error policies.
- Safe rejection JSONL without raw payloads.
- Quality reporting by source, event type, and error code.
- Strict mypy checks and a distributed `py.typed` marker.
- Windows/Linux raw-to-alert end-to-end tests.

## Data flow

```text
raw source record
      |
      v
envelope validation
      |
      v
source adapter
      |
      v
SecurityEvent 1.0.0
      |
      +--> normalized JSONL
      |
      v
DetectionEngine --> Alert
```

## Verification

```powershell
uv sync --locked
uv run ruff check .
uv run mypy
uv run pytest -v
uv build

uv run forgesoc-normalize `
  data/raw/windows_brute_force.jsonl `
  data/normalized/windows_brute_force.jsonl

uv run forgesoc `
  data/normalized/windows_brute_force.jsonl `
  data/alerts.jsonl
```

Repeat the last two commands with `data/raw/linux_brute_force.jsonl`. Each raw
dataset must normalize five events and produce one brute-force alert.

## Concepts introduced

- **Normalization:** converting different source representations into one
  canonical meaning.
- **Adapter Pattern:** source-specific translation behind a shared contract.
- **Boundary schema:** validation types for untrusted input, separate from
  internal domain types.
- **Schema evolution:** explicit versioning of the canonical contract.
- **Data quality:** measuring accepted and rejected records rather than silently
  losing data.
- **Idempotent identity:** the same source record receives the same normalized
  identifier on every run.
- **Discriminated results:** success and failure are explicit types instead of
  ambiguous `None` values.

## Intentional limitations

- Only authentication from two structured sources is normalized.
- Raw text syslog and native Windows XML/EVTX parsing are not supported.
- Results are collected in memory before output to prevent strict-mode partial
  files; this is acceptable for current datasets, not high-volume streaming.
- Rejections omit raw payloads and do not yet support controlled quarantine.
- Stable IDs prepare for deduplication, but duplicate suppression is not yet
  implemented.
- The canonical `attributes` mapping is flexible rather than event-specific.

These limitations should drive later schema, persistence, and streaming work;
they do not justify adding that infrastructure in this sprint.
