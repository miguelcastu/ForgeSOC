# Testing and quality checks

## Complete local verification

```powershell
uv sync
uv run ruff check .
uv run mypy
uv run pytest -v
uv run forgesoc data/security_events.jsonl data/alerts.jsonl
```

## Test layers

- `tests/test_brute_force.py` isolates detector behavior and its state changes.
- `tests/test_behavioral_detections.py` validates every threat-informed rule,
  benign activity, and completeness of the MITRE metadata catalog.
- `tests/test_pipeline.py` exercises ingestion, detection, and output together
  using the committed synthetic dataset and a temporary output file.
- `tests/test_simulation.py` verifies deterministic generation, event contracts,
  scenario meaning, overwrite protection, JSONL round trips, and current
  detection results.
- `tests/test_normalization.py` verifies source mappings, validation failures,
  stable identity, UTC conversion, rejection policy, quality reports, and raw
  Windows/Linux telemetry replayed through detection.
- `tests/test_persistence.py` verifies configuration, mappings, deterministic
  alert identity, and table metadata without requiring a database.
- `tests/test_persistence_postgres.py` verifies migrations, PostgreSQL types,
  idempotency, ordering, transactions, evidence integrity, and a complete
  normalized-event-to-persisted-alert workflow.
- `tests/test_api.py` verifies static assets, OpenAPI, liveness, request IDs,
  and stable error responses without a database.
- `tests/test_api_postgres.py` verifies web operations, filters, cursor
  pagination, import, detection, idempotency, and ordered evidence.

Tests must be deterministic: fixed timestamps and synthetic identities make
failures reproducible. A detection change should include positive and negative
cases and must not rely on network services.

## Ruff

Ruff enforces the rule sets configured in `pyproject.toml`. Run it before every
commit. Automatic fixes can be reviewed with:

```powershell
uv run ruff check . --fix
git diff
```

## Static type checking

```powershell
uv run mypy
```

ForgeSOC publishes the `py.typed` marker so its annotations are available when
the installed package is checked. Mypy runs in strict mode over application
code and is also required by CI.

## PostgreSQL integration tests

Integration tests skip unless an explicitly named test database is provided.
The safety check requires `test` in the database name before it truncates data.

```powershell
docker compose up -d postgres
$env:FORGESOC_DATABASE_URL = "postgresql+psycopg://forgesoc:forgesoc-local-only@localhost:5432/forgesoc_test"
$env:FORGESOC_TEST_DATABASE_URL = $env:FORGESOC_DATABASE_URL
uv run alembic upgrade head
uv run pytest -m postgres -v
uv run alembic check
```

Run `uv run pytest -m "not postgres" -v` for the service-independent subset.
CI provisions PostgreSQL and executes both subsets together.
