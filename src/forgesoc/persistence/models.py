from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IngestionSummary:
    events_received: int
    events_inserted: int
    duplicates: int


@dataclass(frozen=True, slots=True)
class DetectionSummary:
    events_processed: int
    alerts_generated: int
    alerts_inserted: int
    duplicates: int


@dataclass(frozen=True, slots=True)
class DatabaseStats:
    events: int
    alerts: int
    events_by_source: Mapping[str, int]
