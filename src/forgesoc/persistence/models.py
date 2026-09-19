from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from forgesoc.domain.models import Alert, SecurityEvent


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
    events_by_type: Mapping[str, int]
    alerts_by_severity: Mapping[str, int]
    alerts_by_rule: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class EventQuery:
    start: datetime | None = None
    end: datetime | None = None
    event_type: str | None = None
    source: str | None = None
    username: str | None = None
    source_ip: str | None = None
    outcome: str | None = None
    cursor_timestamp: datetime | None = None
    cursor_id: str | None = None
    limit: int = 50


@dataclass(frozen=True, slots=True)
class AlertQuery:
    start: datetime | None = None
    end: datetime | None = None
    severity: str | None = None
    rule_id: str | None = None
    username: str | None = None
    source_ip: str | None = None
    cursor_timestamp: datetime | None = None
    cursor_id: str | None = None
    limit: int = 50


@dataclass(frozen=True, slots=True)
class EventPage:
    items: tuple[SecurityEvent, ...]
    has_more: bool


@dataclass(frozen=True, slots=True)
class AlertPage:
    items: tuple[Alert, ...]
    has_more: bool
