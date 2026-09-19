# ADR-010: Serve a synchronous FastAPI API and buildless web console

- **Status:** Accepted
- **Date:** 2026-09-20

## Context

Persisted events and alerts are useful only to developers comfortable with SQL
or the CLI. ForgeSOC needs a presentable analyst experience and a machine API,
but the current repository has no need for a separately deployed frontend or
asynchronous database stack.

## Decision

Use FastAPI with the existing synchronous SQLAlchemy services. Serve a
framework-free HTML, CSS, and JavaScript console from the same process. Generate
OpenAPI from explicit Pydantic request and response models. Package the static
assets with the Python distribution and keep them independent of external CDNs.

## Alternatives considered

- React/Vue and Node tooling: strong ecosystem, but introduces a second build,
  dependency graph, and deployment before the interface needs that complexity.
- Server-rendered templates: simple, but less suitable for filters, drawers,
  cursor navigation, and live demo actions.
- Async FastAPI and SQLAlchemy: useful for different workloads, but would force
  a persistence rewrite without measured concurrency pressure.

## Consequences

One command serves both UI and API, the workshop works offline, and contracts
remain inspectable through OpenAPI. Frontend code must maintain its own small
component conventions. A dedicated frontend can be introduced later without
changing `/api/v1`.
