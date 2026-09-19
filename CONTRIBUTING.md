# Contributing

ForgeSOC currently uses a lightweight workflow suitable for a personal project.

## Workflow

1. Create a ticket such as `SOCPLAT-005` with scope and acceptance criteria.
2. Branch from `main`: `feature/socplat-005-short-description`.
3. Make small Conventional Commits.
4. Run all local checks.
5. Open a pull request describing the problem, decision, tests, and limitations.
6. Merge only when CI passes.

## Local checks

```powershell
uv sync
uv run ruff check .
uv run mypy
uv run pytest -v
```

Persistence changes also require a reviewed Alembic migration and, with the
test database configured, `uv run alembic check`. Never edit a migration that
has already been shared; add a new revision instead.

API changes must preserve `/api/v1` compatibility, update OpenAPI response
models, and include both success and failure tests. Frontend operations must
remain usable without external CDNs or services.

Do not include real security telemetry or secrets. New detections should have
both positive and negative tests and explain their grouping key, threshold,
time window, severity, and suppression behavior.
