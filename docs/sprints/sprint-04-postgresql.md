# Sprint 4: PostgreSQL persistence

## Goal

Persist normalized events and generated alerts in PostgreSQL so telemetry can
be replayed, queried, deduplicated, and linked to durable detection evidence.

## Delivered capabilities

- PostgreSQL 17 development service through Docker Compose.
- SQLAlchemy 2 typed table mappings and psycopg 3 connectivity.
- Versioned Alembic schema migrations.
- Canonical event storage using `TIMESTAMPTZ`, `INET`, and `JSONB`.
- Alert storage with ordered many-to-many event evidence.
- Idempotency by canonical ID, source record identity, and deterministic alert
  identity.
- Repository boundaries and service-owned transactions.
- Database health, ingestion, detection, and statistics CLI commands.
- Unit tests that need no service and protected PostgreSQL integration tests.
- CI migration round-trip, schema-drift validation, and database smoke tests.

## Data flow

```text
raw JSONL -> normalize -> canonical JSONL -> ingest -> events
                                                   |
UTC time range -> ordered replay -> detector -------+
                              |
                              +-> alerts -> alert_events
```

## Verification

```powershell
uv sync --locked
docker compose up -d postgres
$env:FORGESOC_DATABASE_URL = "postgresql+psycopg://forgesoc:forgesoc-local-only@localhost:5432/forgesoc_test"
$env:FORGESOC_TEST_DATABASE_URL = $env:FORGESOC_DATABASE_URL
uv run alembic upgrade head
uv run alembic check
uv run ruff check .
uv run mypy
uv run pytest -v
uv build
```

Application smoke test:

```powershell
uv run forgesoc-normalize `
  data/raw/windows_brute_force.jsonl `
  data/normalized/windows_brute_force.jsonl
uv run forgesoc-db ingest data/normalized/windows_brute_force.jsonl
uv run forgesoc-db detect `
  --start 2026-09-19T00:00:00Z `
  --end 2026-09-20T00:00:00Z
uv run forgesoc-db stats
```

Repeating ingestion and detection should report duplicates and leave row counts
unchanged.

## Acceptance criteria

- Migrations create and can remove every Sprint 4 table.
- The same event file can be ingested repeatedly without duplicate rows.
- Events are replayed in stable timestamp and ID order.
- Alerts and their ordered evidence are committed atomically.
- Replaying the same detection range does not duplicate alerts.
- A missing evidence event or another exception rolls back the transaction.
- Windows and Linux brute-force datasets each create one persisted alert.
- Ruff, strict mypy, pytest, the package build, and CI all pass.

## Intentional limitations

- The CLI processes bounded historical ranges; it is not a streaming worker.
- Detection state is reconstructed for every invocation.
- The current query guard is a fixed 100,000-event limit rather than paging.
- Retention, partitions, backups, encryption policy, access roles, and production
  monitoring are outside this educational local deployment.
- PostgreSQL integration needs Docker or another dedicated test database and is
  skipped safely when neither is configured.

The next sprint should use measurements from this durable pipeline before
choosing an API, queue, scheduler, or streaming architecture.
