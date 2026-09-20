from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

type JsonValue = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)

CANONICAL_SCHEMA_VERSION = "1.0.0"


class EventType(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHENTICATION_SUCCESS = "authentication.success"
    AUTHENTICATION_FAILURE = "authentication.failure"
    PROCESS_START = "process.start"
    NETWORK_CONNECTION = "network.connection"
    DNS_QUERY = "dns.query"
    HTTP_REQUEST = "http.request"
    PRIVILEGE_USE = "privilege.use"
    SERVICE_INSTALL = "service.install"
    FILE_CHANGE = "file.change"


class AuthenticationOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UserRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AlertStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class AlertDisposition(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"


class CaseStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_type: EventType
    source: str
    username: str | None
    source_ip: str | None
    outcome: AuthenticationOutcome | None
    host: str | None = None
    attributes: Mapping[str, JsonValue] = field(default_factory=dict)
    source_record_id: str | None = None
    schema_version: str = CANONICAL_SCHEMA_VERSION


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
    status: AlertStatus = AlertStatus.OPEN
    assignee: str | None = None
    disposition: AlertDisposition | None = None
