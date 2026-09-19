from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from forgesoc.domain.models import (
    Alert,
    AuthenticationOutcome,
    EventType,
    JsonValue,
    SecurityEvent,
    Severity,
)
from forgesoc.persistence.models import (
    DatabaseStats,
    DetectionSummary,
    IngestionSummary,
)


class EventResponse(BaseModel):
    schema_version: str
    event_id: str
    timestamp: datetime
    event_type: EventType
    source: str
    source_record_id: str | None
    username: str | None
    source_ip: str | None
    outcome: AuthenticationOutcome | None
    host: str | None
    attributes: dict[str, JsonValue]

    @classmethod
    def from_domain(cls, event: SecurityEvent) -> "EventResponse":
        return cls(
            schema_version=event.schema_version,
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            source=event.source,
            source_record_id=event.source_record_id,
            username=event.username,
            source_ip=event.source_ip,
            outcome=event.outcome,
            host=event.host,
            attributes=dict(event.attributes),
        )


class AlertResponse(BaseModel):
    alert_id: str
    timestamp: datetime
    rule_id: str
    title: str
    severity: Severity
    username: str | None
    source_ip: str | None
    related_event_ids: tuple[str, ...]
    reason: str

    @classmethod
    def from_domain(cls, alert: Alert) -> "AlertResponse":
        return cls(
            alert_id=alert.alert_id,
            timestamp=alert.timestamp,
            rule_id=alert.rule_id,
            title=alert.title,
            severity=alert.severity,
            username=alert.username,
            source_ip=alert.source_ip,
            related_event_ids=alert.related_event_ids,
            reason=alert.reason,
        )


class EventPageResponse(BaseModel):
    items: list[EventResponse]
    next_cursor: str | None


class AlertPageResponse(BaseModel):
    items: list[AlertResponse]
    next_cursor: str | None


class StatsResponse(BaseModel):
    events: int
    alerts: int
    events_by_source: dict[str, int]
    events_by_type: dict[str, int]
    alerts_by_severity: dict[str, int]
    alerts_by_rule: dict[str, int]

    @classmethod
    def from_domain(cls, stats: DatabaseStats) -> "StatsResponse":
        return cls(
            events=stats.events,
            alerts=stats.alerts,
            events_by_source=dict(stats.events_by_source),
            events_by_type=dict(stats.events_by_type),
            alerts_by_severity=dict(stats.alerts_by_severity),
            alerts_by_rule=dict(stats.alerts_by_rule),
        )


class IngestionResponse(BaseModel):
    events_received: int
    events_inserted: int
    duplicates: int

    @classmethod
    def from_domain(cls, summary: IngestionSummary) -> "IngestionResponse":
        return cls(
            events_received=summary.events_received,
            events_inserted=summary.events_inserted,
            duplicates=summary.duplicates,
        )


class DetectionResponse(BaseModel):
    events_processed: int
    alerts_generated: int
    alerts_inserted: int
    duplicates: int

    @classmethod
    def from_domain(cls, summary: DetectionSummary) -> "DetectionResponse":
        return cls(
            events_processed=summary.events_processed,
            alerts_generated=summary.alerts_generated,
            alerts_inserted=summary.alerts_inserted,
            duplicates=summary.duplicates,
        )


class DetectionRequest(BaseModel):
    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value


class DemoSeedRequest(BaseModel):
    scenario: str = "brute-force"
    seed: int = 42
    start_time: datetime

    @field_validator("start_time")
    @classmethod
    def require_start_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("start_time must include a timezone")
        return value


class EventInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    event_id: str = Field(min_length=1, max_length=64)
    timestamp: datetime
    event_type: EventType
    source: str = Field(min_length=1, max_length=64)
    source_record_id: str | None = Field(default=None, max_length=255)
    username: str | None = None
    source_ip: IPvAnyAddress | None = None
    outcome: AuthenticationOutcome | None = None
    host: str | None = None
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_event_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value

    def to_domain(self) -> SecurityEvent:
        return SecurityEvent(
            schema_version=self.schema_version,
            event_id=self.event_id,
            timestamp=self.timestamp,
            event_type=self.event_type,
            source=self.source,
            source_record_id=self.source_record_id,
            username=self.username,
            source_ip=str(self.source_ip) if self.source_ip is not None else None,
            outcome=self.outcome,
            host=self.host,
            attributes=self.attributes,
        )


class EventImportRequest(BaseModel):
    events: list[EventInput] = Field(min_length=1, max_length=5_000)


class RawImportRequest(BaseModel):
    records: list[dict[str, JsonValue]] = Field(min_length=1, max_length=5_000)


class RejectionResponse(BaseModel):
    line_number: int
    source_type: str | None
    source_record_id: str | None
    error_code: str
    message: str


class NormalizationIngestionResponse(BaseModel):
    records_received: int
    events_normalized: int
    events_rejected: int
    events_inserted: int
    duplicates: int
    rejections: list[RejectionResponse]


class ScenarioResponse(BaseModel):
    name: str
    description: str


class ErrorResponse(BaseModel):
    code: str
    message: str
    request_id: str
