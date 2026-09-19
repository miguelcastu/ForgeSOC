# Development setup

## Prerequisites

Install Git and uv. Python itself is installed and selected by uv using the
repository's `.python-version` file.

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

## Dependency policy

- Runtime dependencies belong in `[project.dependencies]`.
- Development-only tools belong in `[dependency-groups].dev`.
- Change dependencies with uv so `pyproject.toml` and `uv.lock` remain aligned.
- Commit `uv.lock` because ForgeSOC is an application and reproducible developer
  environments are a project requirement.
