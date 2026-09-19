# ADR-001: Use uv for Python project management

- **Status:** Accepted
- **Date:** 2026-09-19

## Context

ForgeSOC needs a reproducible Python version, isolated environment, dependency
resolution, lock file, and consistent command runner.

## Decision

Use uv to install/select Python 3.12, manage `.venv`, resolve dependencies into
`uv.lock`, synchronize environments, and run commands. Commit
`pyproject.toml`, `.python-version`, and `uv.lock`; never commit `.venv`.

## Alternatives considered

- Standard `venv` plus pip and requirements files: workable, but separates
  environment creation, dependency declarations, and locking.
- Poetry: capable, but adds a different workflow when uv already covers the
  current requirements.

## Consequences

Contributors need uv installed. `uv sync` recreates the locked environment, and
`uv run` executes tools without relying on globally installed project packages.
