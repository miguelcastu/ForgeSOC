# ForgeSOC

ForgeSOC is an educational Open Detection & Response Platform built
incrementally to explore detection engineering, security software engineering,
and SOC platform engineering through working code.

The project deliberately starts as a small synchronous Python application.
Infrastructure such as databases, APIs, and message brokers will only be added
when an observed limitation justifies them.

## Project status

| Capability | Status |
| --- | --- |
| JSONL authentication-event ingestion | Implemented |
| Typed event and alert domain models | Implemented |
| Stateful brute-force detection | Implemented |
| JSONL alert output and CLI | Implemented |
| Synthetic telemetry generator | Planned |
| Normalization, persistence, API, and streaming | Planned |

Current milestone: **Sprint 1 complete — core detection pipeline**.

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

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Python 3.12, installed and managed through uv
- Git

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

The included events and identifiers are entirely synthetic.

## Repository layout

```text
data/                  Synthetic input datasets
docs/                  Architecture, decisions, and sprint documentation
src/forgesoc/domain/   Domain models and controlled vocabularies
src/forgesoc/ingestion JSONL input adapter
src/forgesoc/detection Detection contract, engine, and rules
src/forgesoc/output/   JSONL output adapter
src/forgesoc/main.py   Application composition and CLI
tests/                 Unit and end-to-end pipeline tests
```

## Documentation

- [Product scope](docs/product.md)
- [Architecture overview](docs/architecture/overview.md)
- [Sprint 1](docs/sprints/sprint-01-core.md)
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
