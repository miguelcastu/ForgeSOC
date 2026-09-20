# ForgeSOC

ForgeSOC is an educational Open Detection & Response Platform built
incrementally to explore detection engineering, security software engineering,
and SOC platform engineering through working code.

The project deliberately starts as a small synchronous Python application.
Infrastructure such as databases, APIs, and message brokers will only be added
when an observed limitation justifies them.
<img width="1886" height="837" alt="image" src="https://github.com/user-attachments/assets/4d1260a7-b2dc-4523-8185-decef10ae19d" />


## Project status

| Capability | Status |
| --- | --- |
| JSONL authentication-event ingestion | Implemented |
| Typed event and alert domain models | Implemented |
| Stateful brute-force detection | Implemented |
| JSONL alert output and CLI | Implemented |
| Deterministic synthetic telemetry generator | Implemented |
| Windows/Linux authentication normalization | Implemented |
| PostgreSQL persistence and migrations | Implemented |
| Database-backed replay and detection | Implemented |
| Web console and versioned query API | Implemented |
| Authentication, analyst workflow, and case management | Implemented |
| Threat-informed Windows/Linux detections and MITRE coverage | Implemented |
| Streaming | Planned |

Current milestone: **Sprint 7 complete - threat-informed detection coverage**.

## Implemented pipeline

```text
security_events.jsonl
        |
        v
  JSONL ingestion
        |
        v
  SecurityEvent
        |
        v
 DetectionEngine
        |
        v
BruteForceDetector
        |
        v
      Alert
        |
        v
   alerts.jsonl
```

The initial rule is `AUTH-BRUTEFORCE-001`:

- five or more failed authentications;
- same username and source IP;
- within a 60-second sliding window;
- high severity;
- a successful login resets the tracked failures;
- one alert per continuous burst to prevent alert spam.

Sprint 7 adds password spraying, suspicious PowerShell, credential dumping,
high-risk sudo, suspicious service persistence, and DNS beaconing rules. Every
rule declares required telemetry, platforms, severity, and MITRE ATT&CK mapping
in the executable detection catalog.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Python 3.12, installed and managed through uv
- Git
- Docker Desktop (only for the PostgreSQL workflow)

The project does not depend on a globally installed Python environment.

## Quick start

From PowerShell in the repository root:

```powershell
uv sync
uv run ruff check .
uv run pytest -v
uv run forgesoc data/security_events.jsonl data/alerts.jsonl
Get-Content data/alerts.jsonl
```

Expected application output:

```text
ForgeSOC generated 1 alert(s).
```

## Generate synthetic telemetry

List the available scenarios:

```powershell
uv run forgesoc-generate --list-scenarios
```

Generate and replay a deterministic brute-force scenario:

```powershell
uv run forgesoc-generate `
  --scenario brute-force `
  --seed 42 `
  --output data/generated/brute-force.jsonl

uv run forgesoc `
  data/generated/brute-force.jsonl `
  data/alerts.jsonl
```

Generation refuses to replace an existing dataset. Pass `--force` only when
replacement is intentional. The same scenario, seed, and start time produce the
same telemetry.

The included events and identifiers are entirely synthetic.

## Normalize source telemetry

ForgeSOC normalizes Windows Security `4624`/`4625`/`4688`/`4697`, Sysmon
`1`/`3`/`22`, structured Linux SSH, and Linux auditd execution, privilege,
file, and service records into the same canonical schema.

```powershell
uv run forgesoc-normalize --list-sources

uv run forgesoc-normalize `
  data/raw/windows_brute_force.jsonl `
  data/normalized/windows_brute_force.jsonl

uv run forgesoc `
  data/normalized/windows_brute_force.jsonl `
  data/alerts.jsonl
```

Normalization is strict by default. To continue after invalid records, provide
an explicit rejection file:

```powershell
uv run forgesoc-normalize `
  data/raw/mixed.jsonl `
  data/normalized/mixed.jsonl `
  --continue-on-error `
  --rejected-output data/rejected/mixed.jsonl
```

The CLI reports totals by source, event type, and error code. Rejection records
contain error context but intentionally omit the raw payload.

## Persist and detect with PostgreSQL

Copy the example configuration, start the local database, and apply migrations:

```powershell
Copy-Item .env.example .env
docker compose up -d postgres
$env:FORGESOC_DATABASE_URL = "postgresql+psycopg://forgesoc:forgesoc-local-only@localhost:5432/forgesoc_dev"
uv run alembic upgrade head
uv run forgesoc-db health
```

Normalize raw telemetry, ingest it idempotently, and run detection over a UTC
time range:

```powershell
uv run forgesoc-normalize `
  data/raw/windows_brute_force.jsonl `
  data/normalized/windows_brute_force.jsonl

uv run forgesoc-db ingest data/normalized/windows_brute_force.jsonl
uv run forgesoc-db detect `
  --start 2025-01-01T00:00:00Z `
  --end 2027-01-01T00:00:00Z
uv run forgesoc-db stats
```

Ingestion and alert writes are transactional and safe to repeat. The database
keeps canonical events, alerts, and the ordered event evidence for each alert.

## Launch the web console

The web console replaces the normal demonstration workflow previously spread
across several CLI commands. It provides dashboards, event search, alert
investigation, ordered evidence, canonical or raw Windows/Linux JSONL import,
scenario generation, detection execution, OpenAPI, and an embedded workshop
architecture guide.

```powershell
docker compose up -d postgres
$env:FORGESOC_DATABASE_URL = "postgresql+psycopg://forgesoc:forgesoc-local-only@localhost:5432/forgesoc_dev"
uv run alembic upgrade head
uv run forgesoc-web
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Alternatively, build and
run both PostgreSQL and the web application with `docker compose up --build`.

On the first visit, create the initial administrator with a password of at least
12 characters. Later users can be created from the Administration page. The
console supports `admin`, `analyst`, and read-only `viewer` roles, alert
assignment and resolution, investigation notes, cases, and an audit trail.

The API documentation is available at
[http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs). The server
binds to localhost by default. Set a strong `FORGESOC_SESSION_SECRET` before
sharing a deployment; ForgeSOC is still an educational application and should
not be exposed directly to the Internet.

## Repository layout

```text
data/                  Synthetic input datasets
docs/                  Architecture, decisions, and sprint documentation
src/forgesoc/domain/   Domain models and controlled vocabularies
src/forgesoc/ingestion JSONL input adapter
src/forgesoc/detection Detection contract, engine, and rules
src/forgesoc/output/   JSONL output adapter
src/forgesoc/simulation/ Deterministic generator and scenario catalog
src/forgesoc/normalization/ Source validation and normalization adapters
src/forgesoc/persistence/ PostgreSQL mappings, repositories, and services
src/forgesoc/api/       FastAPI, web console, and public response contracts
src/forgesoc/main.py   Application composition and CLI
migrations/            Versioned Alembic database migrations
docker/                Local PostgreSQL initialization
tests/                 Unit and end-to-end pipeline tests
```

## Documentation

- [Product scope](docs/product.md)
- [Architecture overview](docs/architecture/overview.md)
- [Sprint 1](docs/sprints/sprint-01-core.md)
- [Sprint 2](docs/sprints/sprint-02-telemetry-generator.md)
- [Sprint 3](docs/sprints/sprint-03-normalization.md)
- [Sprint 4](docs/sprints/sprint-04-postgresql.md)
- [Sprint 5](docs/sprints/sprint-05-web-console.md)
- [Sprint 6](docs/sprints/sprint-06-analyst-workflow.md)
- [Sprint 7](docs/sprints/sprint-07-threat-informed-detections.md)
- [Windows/Linux threat model](docs/threat-model/windows-linux.md)
- [Scenario catalog](docs/scenarios.md)
- [Normalization mappings](docs/normalization.md)
- [Persistence architecture](docs/architecture/persistence.md)
- [Web API architecture](docs/architecture/web-api.md)
- [Development setup](docs/development/setup.md)
- [Testing](docs/development/testing.md)
- [Git and GitHub workflow](docs/development/git-workflow.md)
- [Architecture Decision Records](docs/adr/)
- [Security policy](SECURITY.md)

## Development workflow

The lightweight workflow for this individual project is:

```text
main <- pull request <- feature/socplat-XXX-short-description
```

Use small Conventional Commits such as `feat:`, `fix:`, `test:`, `docs:`, and
`chore:`. Pull requests should pass Ruff and pytest before merging.

## Security

Never commit real telemetry, credentials, tokens, API keys, or personal data.
See [SECURITY.md](SECURITY.md) for reporting and data-handling guidance.

## License

No license has been selected yet. Until one is added, copyright remains with
the repository owner and reuse is not granted automatically.
