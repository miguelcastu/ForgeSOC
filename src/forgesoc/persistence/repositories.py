from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from forgesoc.domain.models import Alert, SecurityEvent
from forgesoc.persistence.mappers import alert_from_row, event_from_row
from forgesoc.persistence.tables import AlertEventRow, AlertRow, EventRow


class MissingRelatedEventsError(ValueError):
    """Raised when alert evidence refers to events absent from storage."""


class EventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_many(self, events: Iterable[SecurityEvent]) -> int:
        values = [self._values(event) for event in events]
        if not values:
            return 0

        statement = (
            insert(EventRow)
            .values(values)
            .on_conflict_do_nothing()
            .returning(EventRow.event_id)
        )
        return len(list(self._session.scalars(statement)))

    def get(self, event_id: str) -> SecurityEvent | None:
        row = self._session.get(EventRow, event_id)
        return event_from_row(row) if row is not None else None

    def list_between(
        self,
        start: datetime,
        end: datetime,
        *,
        event_type: str | None = None,
        limit: int = 100_000,
    ) -> list[SecurityEvent]:
        statement = (
            select(EventRow)
            .where(EventRow.timestamp >= start, EventRow.timestamp < end)
            .order_by(EventRow.timestamp, EventRow.event_id)
            .limit(limit)
        )
        if event_type is not None:
            statement = statement.where(EventRow.event_type == event_type)

        return [event_from_row(row) for row in self._session.scalars(statement)]

    def count(self) -> int:
        return self._session.scalar(select(func.count()).select_from(EventRow)) or 0

    def counts_by_source(self) -> dict[str, int]:
        statement = (
            select(EventRow.source, func.count())
            .group_by(EventRow.source)
            .order_by(EventRow.source)
        )
        return {source: count for source, count in self._session.execute(statement)}

    @staticmethod
    def _values(event: SecurityEvent) -> dict[str, object]:
        return {
            "event_id": event.event_id,
            "schema_version": event.schema_version,
            "timestamp": event.timestamp,
            "event_type": event.event_type.value,
            "source": event.source,
            "source_record_id": event.source_record_id,
            "username": event.username,
            "source_ip": event.source_ip,
            "outcome": event.outcome.value if event.outcome is not None else None,
            "host": event.host,
            "attributes": dict(event.attributes),
        }


class AlertRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, alert: Alert) -> bool:
        if len(set(alert.related_event_ids)) != len(alert.related_event_ids):
            raise ValueError("alert evidence contains duplicate event IDs")

        existing_event_ids = set(
            self._session.scalars(
                select(EventRow.event_id).where(
                    EventRow.event_id.in_(alert.related_event_ids)
                )
            )
        )
        missing = set(alert.related_event_ids) - existing_event_ids
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise MissingRelatedEventsError(
                f"alert references missing events: {missing_list}"
            )

        alert_id = UUID(alert.alert_id)
        statement = (
            insert(AlertRow)
            .values(
                alert_id=alert_id,
                timestamp=alert.timestamp,
                rule_id=alert.rule_id,
                title=alert.title,
                severity=alert.severity.value,
                username=alert.username,
                source_ip=alert.source_ip,
                reason=alert.reason,
            )
            .on_conflict_do_nothing(index_elements=[AlertRow.alert_id])
            .returning(AlertRow.alert_id)
        )
        inserted_id = self._session.scalar(statement)
        if inserted_id is None:
            return False

        evidence_values = [
            {
                "alert_id": alert_id,
                "event_id": event_id,
                "evidence_order": position,
            }
            for position, event_id in enumerate(alert.related_event_ids)
        ]
        if evidence_values:
            self._session.execute(insert(AlertEventRow).values(evidence_values))

        return True

    def add_many(self, alerts: Iterable[Alert]) -> int:
        return sum(self.add(alert) for alert in alerts)

    def get(self, alert_id: str) -> Alert | None:
        identifier = UUID(alert_id)
        row = self._session.get(AlertRow, identifier)
        if row is None:
            return None

        evidence_statement = (
            select(AlertEventRow.event_id)
            .where(AlertEventRow.alert_id == identifier)
            .order_by(AlertEventRow.evidence_order)
        )
        evidence = tuple(self._session.scalars(evidence_statement))
        return alert_from_row(row, evidence)

    def count(self) -> int:
        return self._session.scalar(select(func.count()).select_from(AlertRow)) or 0
