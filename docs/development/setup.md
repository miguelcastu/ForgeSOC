# Development setup

## Prerequisites

Install Git and uv. Install Docker Desktop as well when working on persistence.
Python itself is installed and selected by uv using the repository's
`.python-version` file.

## Windows and PowerShell

```powershell
git clone <repository-url>
Set-Location ForgeSOC
uv sync
uv run pytest -v
```

`uv sync` creates or updates `.venv` from `pyproject.toml` and `uv.lock`. Do not
activate the environment manually and do not commit `.venv`.

## Run ForgeSOC

```powershell
uv run forgesoc data/security_events.jsonl data/alerts.jsonl
Get-Content data/alerts.jsonl
```

## Run PostgreSQL locally

The committed Compose configuration is for development only and binds
PostgreSQL to localhost.

```powershell
Copy-Item .env.example .env
docker compose up -d postgres
$env:FORGESOC_DATABASE_URL = "postgresql+psycopg://forgesoc:forgesoc-local-only@localhost:5432/forgesoc_dev"
uv run alembic upgrade head
uv run forgesoc-db health
```

PowerShell does not automatically load `.env` into the current shell. Set the
variable as shown above, or use your preferred environment loader. Never commit
the resulting `.env` file.

Useful lifecycle commands:

```powershell
docker compose ps
docker compose logs postgres
docker compose down
```

`docker compose down -v` also deletes the local database volume and all stored
events and alerts. Use it only when a complete local reset is intentional.

## Database migrations

Apply all migrations after starting PostgreSQL:

```powershell
uv run alembic upgrade head
```

After intentionally changing the SQLAlchemy table definitions, create and
review a migration instead of relying blindly on generated output:

```powershell
uv run alembic revision --autogenerate -m "describe schema change"
uv run alembic check
```

## Dependency policy

- Runtime dependencies belong in `[project.dependencies]`.
- Development-only tools belong in `[dependency-groups].dev`.
- Change dependencies with uv so `pyproject.toml` and `uv.lock` remain aligned.
- Commit `uv.lock` because ForgeSOC is an application and reproducible developer
  environments are a project requirement.
