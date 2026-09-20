# ADR-014: Executable detection metadata registry

## Status

Accepted in Sprint 7.

## Context

Coverage pages maintained separately from executable detections drift quickly.
Rules also need consistent platform, telemetry, severity, and MITRE ATT&CK
metadata for analysts and detection engineers.

## Decision

Every detector exposes typed `DetectionMetadata`. A single registry constructs
the enabled detectors and exposes their metadata to alerts, scenario profiles,
OpenAPI responses, and the coverage page. Rule code remains the source of truth.

## Consequences

- Adding a detector requires complete metadata and automatically updates the UI.
- Alerts resolve ATT&CK context from their stable rule ID without duplicating
  framework metadata in every database row.
- Historical alerts depend on preserving catalog entries for retired rule IDs.
- ATT&CK mappings still require human review and version maintenance.
