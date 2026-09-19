from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class EventType(StrEnum):
    AUTHENTICATION = "authentication"


class AuthenticationOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_type: EventType
    source: str
    username: str | None
    source_ip: str | None
    outcome: AuthenticationOutcome | None


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    timestamp: datetime
    rule_id: str
    title: str
    severity: Severity

    username: str | None
    source_ip: str | None

    related_event_ids: tuple[str, ...]
    reason: str