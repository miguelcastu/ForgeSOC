from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from forgesoc.domain.models import Alert, SecurityEvent
from forgesoc.persistence.mappers import alert_from_row, event_from_row
from forgesoc.persistence.models import AlertPage, AlertQuery, EventPage, EventQuery
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

    def counts_by_type(self) -> dict[str, int]:
        statement = (
            select(EventRow.event_type, func.count())
            .group_by(EventRow.event_type)
            .order_by(EventRow.event_type)
        )
        return {
            event_type: count
            for event_type, count in self._session.execute(statement)
        }

    def search(self, query: EventQuery) -> EventPage:
        statement = select(EventRow)
        if query.start is not None:
            statement = statement.where(EventRow.timestamp >= query.start)
        if query.end is not None:
            statement = statement.where(EventRow.timestamp < query.end)
        if query.event_type is not None:
            statement = statement.where(EventRow.event_type == query.event_type)
        if query.source is not None:
            statement = statement.where(EventRow.source == query.source)
        if query.username is not None:
            statement = statement.where(EventRow.username.ilike(f"%{query.username}%"))
        if query.source_ip is not None:
            statement = statement.where(EventRow.source_ip == query.source_ip)
        if query.outcome is not None:
            statement = statement.where(EventRow.outcome == query.outcome)
        if query.cursor_timestamp is not None and query.cursor_id is not None:
            statement = statement.where(
                or_(
                    EventRow.timestamp < query.cursor_timestamp,
                    and_(
                        EventRow.timestamp == query.cursor_timestamp,
                        EventRow.event_id < query.cursor_id,
                    ),
                )
            )

        rows = list(
            self._session.scalars(
                statement.order_by(
                    EventRow.timestamp.desc(),
                    EventRow.event_id.desc(),
                ).limit(query.limit + 1)
            )
        )
        return EventPage(
            items=tuple(event_from_row(row) for row in rows[: query.limit]),
            has_more=len(rows) > query.limit,
        )

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

    def counts_by_severity(self) -> dict[str, int]:
        statement = (
            select(AlertRow.severity, func.count())
            .group_by(AlertRow.severity)
            .order_by(AlertRow.severity)
        )
        return {severity: count for severity, count in self._session.execute(statement)}

    def counts_by_rule(self) -> dict[str, int]:
        statement = (
            select(AlertRow.rule_id, func.count())
            .group_by(AlertRow.rule_id)
            .order_by(AlertRow.rule_id)
        )
        return {rule_id: count for rule_id, count in self._session.execute(statement)}

    def search(self, query: AlertQuery) -> AlertPage:
        statement = select(AlertRow)
        if query.start is not None:
            statement = statement.where(AlertRow.timestamp >= query.start)
        if query.end is not None:
            statement = statement.where(AlertRow.timestamp < query.end)
        if query.severity is not None:
            statement = statement.where(AlertRow.severity == query.severity)
        if query.rule_id is not None:
            statement = statement.where(AlertRow.rule_id == query.rule_id)
        if query.username is not None:
            statement = statement.where(AlertRow.username.ilike(f"%{query.username}%"))
        if query.source_ip is not None:
            statement = statement.where(AlertRow.source_ip == query.source_ip)
        if query.cursor_timestamp is not None and query.cursor_id is not None:
            cursor_uuid = UUID(query.cursor_id)
            statement = statement.where(
                or_(
                    AlertRow.timestamp < query.cursor_timestamp,
                    and_(
                        AlertRow.timestamp == query.cursor_timestamp,
                        AlertRow.alert_id < cursor_uuid,
                    ),
                )
            )

        rows = list(
            self._session.scalars(
                statement.order_by(
                    AlertRow.timestamp.desc(),
                    AlertRow.alert_id.desc(),
                ).limit(query.limit + 1)
            )
        )
        page_rows = rows[: query.limit]
        identifiers = [row.alert_id for row in page_rows]
        evidence_by_alert: dict[UUID, list[str]] = {
            identifier: [] for identifier in identifiers
        }
        if identifiers:
            evidence_statement = (
                select(AlertEventRow.alert_id, AlertEventRow.event_id)
                .where(AlertEventRow.alert_id.in_(identifiers))
                .order_by(AlertEventRow.alert_id, AlertEventRow.evidence_order)
            )
            for alert_id, event_id in self._session.execute(evidence_statement):
                evidence_by_alert[alert_id].append(event_id)
        alerts = tuple(
            alert_from_row(row, tuple(evidence_by_alert[row.alert_id]))
            for row in page_rows
        )
        return AlertPage(items=alerts, has_more=len(rows) > query.limit)

    def evidence(self, alert_id: str) -> tuple[SecurityEvent, ...] | None:
        identifier = UUID(alert_id)
        if self._session.get(AlertRow, identifier) is None:
            return None
        statement = (
            select(EventRow)
            .join(AlertEventRow, AlertEventRow.event_id == EventRow.event_id)
            .where(AlertEventRow.alert_id == identifier)
            .order_by(AlertEventRow.evidence_order)
        )
        return tuple(event_from_row(row) for row in self._session.scalars(statement))
