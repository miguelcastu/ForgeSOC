from collections.abc import Iterable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from forgesoc.domain.models import Alert, SecurityEvent
from forgesoc.persistence.mappers import alert_from_row, event_from_row
from forgesoc.persistence.models import (
    AlertNoteRecord,
    AlertPage,
    AlertQuery,
    AuditRecord,
    CaseRecord,
    EventPage,
    EventQuery,
    UserRecord,
)
from forgesoc.persistence.tables import (
    AlertEventRow,
    AlertNoteRow,
    AlertRow,
    AuditLogRow,
    CaseAlertRow,
    CaseRow,
    EventRow,
    UserRow,
)


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
            event_type: count for event_type, count in self._session.execute(statement)
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
        assignee = None
        if row.assignee_user_id is not None:
            assignee = self._session.scalar(
                select(UserRow.username).where(UserRow.user_id == row.assignee_user_id)
            )
        return alert_from_row(row, evidence, assignee)

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
        if query.status is not None:
            statement = statement.where(AlertRow.status == query.status)
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
        assignee_ids = {
            row.assignee_user_id
            for row in page_rows
            if row.assignee_user_id is not None
        }
        assignees: dict[UUID, str] = {}
        if assignee_ids:
            assignee_statement = select(UserRow.user_id, UserRow.username).where(
                UserRow.user_id.in_(assignee_ids)
            )
            for user_id, username in self._session.execute(assignee_statement):
                assignees[user_id] = username
        alerts = tuple(
            alert_from_row(
                row,
                tuple(evidence_by_alert[row.alert_id]),
                (
                    assignees.get(row.assignee_user_id)
                    if row.assignee_user_id is not None
                    else None
                ),
            )
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

    def update_workflow(
        self,
        alert_id: str,
        *,
        status: str,
        assignee_user_id: UUID | None,
        disposition: str | None,
    ) -> bool:
        row = self._session.get(AlertRow, UUID(alert_id))
        if row is None:
            return False
        row.status = status
        row.assignee_user_id = assignee_user_id
        row.disposition = disposition
        row.updated_at = datetime.now(UTC)
        return True


class UserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def count(self) -> int:
        return self._session.scalar(select(func.count()).select_from(UserRow)) or 0

    def create(self, username: str, password_hash: str, role: str) -> UserRecord:
        row = UserRow(
            user_id=uuid4(),
            username=username,
            password_hash=password_hash,
            role=role,
            active=True,
        )
        self._session.add(row)
        self._session.flush()
        return self._record(row)

    def by_username(self, username: str) -> UserRow | None:
        return self._session.scalar(
            select(UserRow).where(func.lower(UserRow.username) == username.lower())
        )

    def get(self, user_id: str) -> UserRow | None:
        return self._session.get(UserRow, UUID(user_id))

    def list(self) -> tuple[UserRecord, ...]:
        rows = self._session.scalars(select(UserRow).order_by(UserRow.username))
        return tuple(self._record(row) for row in rows)

    @staticmethod
    def _record(row: UserRow) -> UserRecord:
        return UserRecord(
            user_id=str(row.user_id),
            username=row.username,
            role=row.role,
            active=row.active,
            created_at=row.created_at,
        )


class WorkflowRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_note(self, alert_id: str, author_id: str, body: str) -> AlertNoteRecord:
        row = AlertNoteRow(
            note_id=uuid4(),
            alert_id=UUID(alert_id),
            author_user_id=UUID(author_id),
            body=body,
        )
        self._session.add(row)
        self._session.flush()
        author = self._session.get(UserRow, row.author_user_id)
        assert author is not None
        return AlertNoteRecord(
            note_id=str(row.note_id),
            alert_id=alert_id,
            author=author.username,
            body=row.body,
            created_at=row.created_at,
        )

    def notes(self, alert_id: str) -> tuple[AlertNoteRecord, ...]:
        statement = (
            select(AlertNoteRow, UserRow.username)
            .join(UserRow, UserRow.user_id == AlertNoteRow.author_user_id)
            .where(AlertNoteRow.alert_id == UUID(alert_id))
            .order_by(AlertNoteRow.created_at)
        )
        return tuple(
            AlertNoteRecord(
                note_id=str(row.note_id),
                alert_id=str(row.alert_id),
                author=username,
                body=row.body,
                created_at=row.created_at,
            )
            for row, username in self._session.execute(statement)
        )

    def create_case(
        self,
        *,
        title: str,
        description: str,
        priority: str,
        assignee_user_id: UUID | None,
        created_by_user_id: UUID,
        alert_ids: tuple[str, ...],
    ) -> CaseRecord:
        row = CaseRow(
            case_id=uuid4(),
            title=title,
            description=description,
            status="open",
            priority=priority,
            assignee_user_id=assignee_user_id,
            created_by_user_id=created_by_user_id,
        )
        self._session.add(row)
        self._session.flush()
        for alert_id in alert_ids:
            self._session.add(
                CaseAlertRow(case_id=row.case_id, alert_id=UUID(alert_id))
            )
        self._session.flush()
        return self._case_record(row, alert_ids)

    def list_cases(self) -> tuple[CaseRecord, ...]:
        rows = self._session.scalars(
            select(CaseRow).order_by(CaseRow.updated_at.desc())
        )
        return tuple(self._case_record(row) for row in rows)

    def update_case(
        self, case_id: str, *, status: str, assignee_user_id: UUID | None
    ) -> CaseRecord | None:
        row = self._session.get(CaseRow, UUID(case_id))
        if row is None:
            return None
        row.status = status
        row.assignee_user_id = assignee_user_id
        row.updated_at = datetime.now(UTC)
        self._session.flush()
        return self._case_record(row)

    def audit(
        self,
        *,
        actor_user_id: str | None,
        action: str,
        entity_type: str,
        entity_id: str,
        details: dict[str, object] | None = None,
    ) -> None:
        self._session.add(
            AuditLogRow(
                audit_id=uuid4(),
                actor_user_id=UUID(actor_user_id) if actor_user_id else None,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details or {},
            )
        )

    def audit_log(self, limit: int = 100) -> tuple[AuditRecord, ...]:
        statement = (
            select(AuditLogRow, UserRow.username)
            .outerjoin(UserRow, UserRow.user_id == AuditLogRow.actor_user_id)
            .order_by(AuditLogRow.timestamp.desc())
            .limit(limit)
        )
        return tuple(
            AuditRecord(
                audit_id=str(row.audit_id),
                timestamp=row.timestamp,
                actor=username,
                action=row.action,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                details=dict(row.details),
            )
            for row, username in self._session.execute(statement)
        )

    def _case_record(
        self, row: CaseRow, known_alert_ids: tuple[str, ...] | None = None
    ) -> CaseRecord:
        alert_ids = known_alert_ids or tuple(
            str(value)
            for value in self._session.scalars(
                select(CaseAlertRow.alert_id).where(CaseAlertRow.case_id == row.case_id)
            )
        )
        assignee = (
            self._session.scalar(
                select(UserRow.username).where(UserRow.user_id == row.assignee_user_id)
            )
            if row.assignee_user_id is not None
            else None
        )
        creator = self._session.scalar(
            select(UserRow.username).where(UserRow.user_id == row.created_by_user_id)
        )
        assert creator is not None
        return CaseRecord(
            case_id=str(row.case_id),
            title=row.title,
            description=row.description,
            status=row.status,
            priority=row.priority,
            assignee=assignee,
            created_by=creator,
            alert_ids=alert_ids,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
