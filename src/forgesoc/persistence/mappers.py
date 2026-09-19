from uuid import UUID

from forgesoc.domain.models import (
    Alert,
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
    Severity,
)
from forgesoc.persistence.tables import AlertRow, EventRow


def event_to_row(event: SecurityEvent) -> EventRow:
    return EventRow(
        event_id=event.event_id,
        schema_version=event.schema_version,
        timestamp=event.timestamp,
        event_type=event.event_type.value,
        source=event.source,
        source_record_id=event.source_record_id,
        username=event.username,
        source_ip=event.source_ip,
        outcome=event.outcome.value if event.outcome is not None else None,
        host=event.host,
        attributes=dict(event.attributes),
    )


def event_from_row(row: EventRow) -> SecurityEvent:
    return SecurityEvent(
        event_id=row.event_id,
        schema_version=row.schema_version,
        timestamp=row.timestamp,
        event_type=EventType(row.event_type),
        source=row.source,
        source_record_id=row.source_record_id,
        username=row.username,
        source_ip=str(row.source_ip) if row.source_ip is not None else None,
        outcome=(
            AuthenticationOutcome(row.outcome) if row.outcome is not None else None
        ),
        host=row.host,
        attributes=dict(row.attributes),
    )


def alert_to_row(alert: Alert) -> AlertRow:
    return AlertRow(
        alert_id=UUID(alert.alert_id),
        timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        title=alert.title,
        severity=alert.severity.value,
        username=alert.username,
        source_ip=alert.source_ip,
        reason=alert.reason,
    )


def alert_from_row(
    row: AlertRow,
    related_event_ids: tuple[str, ...],
) -> Alert:
    return Alert(
        alert_id=str(row.alert_id),
        timestamp=row.timestamp,
        rule_id=row.rule_id,
        title=row.title,
        severity=Severity(row.severity),
        username=row.username,
        source_ip=str(row.source_ip) if row.source_ip is not None else None,
        related_event_ids=related_event_ids,
        reason=row.reason,
    )
