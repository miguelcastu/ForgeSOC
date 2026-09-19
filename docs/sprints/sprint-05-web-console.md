# Sprint 5: analyst web console and query API

## Goal

Make ForgeSOC demonstrable and operable from one browser experience while
preserving the typed, testable boundaries built in earlier sprints.

## Delivered capabilities

- Responsive dark analyst console with overview, events, alerts, and workshop
  sections.
- Versioned synchronous FastAPI application and interactive OpenAPI.
- Cursor pagination and safe filtering for events and alerts.
- Alert investigation with ordered event evidence.
- Dashboard statistics by source, event type, severity, and rule.
- Canonical and raw Windows/Linux JSONL browser import with rejection feedback.
- Deterministic scenario generation and browser-triggered detection.
- Stable error responses, request IDs, timing headers, and readiness checks.
- Docker image and Compose API service.
- CI web smoke tests and PostgreSQL-backed API integration tests.

## Five-minute demonstration

1. Open Overview and explain the platform posture and telemetry mix.
2. Open Workshop and walk left-to-right through the architecture diagram.
3. Generate the `brute-force` scenario from the page.
4. Open Events and show six canonical authentication failures.
5. Run detection from Alerts.
6. Open the finding and show the five ordered evidence events.
7. Repeat generation or detection to show idempotent duplicate counts.
8. Finish at `/api/docs` to demonstrate the versioned machine interface.

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
uv run forgesoc-web
```

For the fully containerized experience, run `docker compose up --build` and
open `http://127.0.0.1:8000`.

## Acceptance criteria

- An analyst can explore and filter events without SQL.
- An alert exposes the exact ordered evidence used by its rule.
- A complete scenario-to-alert demonstration requires no data CLI.
- Pagination remains stable when new rows are added.
- Invalid input and missing resources return safe structured errors.
- The architecture and workshop story are available inside the product.
- The package, container, migrations, types, tests, and CI smoke flow pass.

## Limitations and next steps

The console is local and unauthenticated. A later analyst-workflow sprint can
add identity, roles, alert ownership, status, comments, and case timelines.
Streaming ingestion and multi-process detection remain separate architectural
decisions.
