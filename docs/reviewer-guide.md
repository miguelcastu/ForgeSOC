# Reviewer guide

[Overview](../README.md) · [Quick start](../README.md#quick-start)
· [Architecture](architecture/overview.md) · [Testing](development/testing.md)
· [ADRs](adr/) · [Security](../SECURITY.md)

## Two-minute overview

ForgeSOC turns synthetic telemetry into explainable alerts and analyst workflows.
Try the committed file pipeline without Docker:

```shell
uv sync --locked
uv run forgesoc data/security_events.jsonl data/alerts.jsonl
uv run pytest -m "not postgres" -q
```

The fixture produces one brute-force finding. This verifies a local pipeline,
not PostgreSQL, a running console or production detection accuracy. The
[console workflow](../README.md#launch-the-web-console) requires a local database,
migrations and initial administrator setup. Do not treat a skipped integration
test as a passing database test.

## Five-minute implementation tour

| Boundary | Implementation | Decision / limitation |
| --- | --- | --- |
| Source adapters | `src/forgesoc/normalization/` | Windows Security/Sysmon and structured Linux sources map to one versioned schema; unknown sources fail explicitly. |
| Canonical events | `domain/models.py`, `ingestion/jsonl.py` | Typed frozen models and boundary validation keep provider shapes out of rules. See [normalization contracts](normalization.md). |
| Rule execution | `detection/base.py`, `engine.py`, `registry.py` | Structural `Detector` protocol; `process(event)` returns alerts. A common metadata registry drives execution and coverage. |
| Stateful rules | `detection/brute_force.py`, `behavioral.py` | Detectors own in-memory state. File replay assumes ordered timestamps; database replay explicitly sorts events. State is not durable across processes. |
| Persistence | `persistence/services.py`, `repositories.py` | Services own transactions; PostgreSQL conflict handling and deterministic alert identity make replay idempotent. See [database architecture](architecture/persistence.md). |
| API and console | `api/app.py`, `api/schemas.py`, `api/static/index.html` | Versioned responses, request IDs and cursor pagination expose canonical records and ordered evidence. See [API design](architecture/web-api.md). |
| Analyst workflow | `api/security.py`, `persistence/repositories.py` | Local admin/analyst/viewer roles, assignments, notes, cases and audit records; not enterprise identity federation. |

The domain and detectors do not import SQLAlchemy. That separation lets tests
exercise normalization and detection without provisioning infrastructure.
Database-backed ingestion materializes batches in memory; it is not a distributed
stream processor. Replay over an insufficient time window can miss earlier
stateful context. Idempotent inserts do not establish semantic equivalence for
conflicting source payloads; inspect duplicate handling before extending ingestion.

## Verify behavior and failure handling

The [testing guide](development/testing.md) maps each suite to a boundary.
Start with `test_behavioral_detections.py` and `test_normalization.py`, then
`test_persistence_postgres.py` and `test_api_postgres.py` with an isolated test
database. [CI](../.github/workflows/ci.yml) provisions PostgreSQL, checks migration
up/down behavior, Ruff, strict Mypy, tests, builds and CLI/API smoke paths.

Malformed JSONL stops file replay. Normalization can instead write a separate
rejection report when explicitly requested; raw rejected payloads are omitted.
API errors use stable codes and request IDs. See [boundary-validation ADR](adr/ADR-006-boundary-validation.md)
and [transaction ADR](adr/ADR-009-idempotency-and-transactions.md).

## Reproduce an analyst demonstration

Use the README's database and console setup. Bootstrap a local administrator,
generate a deterministic scenario, run detection, open the alert and follow its
ordered source events. Compare coverage against the registry, add an investigation
note and create a case. These are implemented local operations, not a mocked UI.
Existing screenshots are historical author-provided images; no new running-console
screenshot is claimed by this documentation change.

## Questions worth exploring

- How do successful authentications reset a brute-force burst without alert spam?
- How do source identity and alert UUIDs affect repeated ingestion?
- What state is lost when a process restarts or a replay window is shortened?
- Which schema and API changes require migrations or compatibility work?
- Which tests need PostgreSQL, and which failures can be reproduced with a fixture alone?

Streaming transport, production hardening, Internet-facing identity and autonomous
remediation remain outside the accepted scope. Use `docker compose down` to stop
local services; retain volumes unless deleting local data is intentional.
