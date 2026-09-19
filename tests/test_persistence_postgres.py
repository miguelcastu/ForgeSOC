import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from forgesoc.detection.brute_force import BruteForceDetector
from forgesoc.domain.models import (
    Alert,
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
    Severity,
)
from forgesoc.ingestion.jsonl import read_events
from forgesoc.normalization.main import run_normalization
from forgesoc.persistence.database import SessionFactory
from forgesoc.persistence.repositories import (
    AlertRepository,
    EventRepository,
    MissingRelatedEventsError,
)
from forgesoc.persistence.services import (
    DatabaseDetectionService,
    EventIngestionService,
)

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv("FORGESOC_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("FORGESOC_TEST_DATABASE_URL is not configured")

    database_name = make_url(database_url).database or ""
    if "test" not in database_name.lower():
        pytest.fail("refusing to run destructive tests outside a test database")

    engine = create_engine(database_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(postgres_engine: Engine) -> Iterator[SessionFactory]:
    factory = sessionmaker(
        bind=postgres_engine,
        class_=Session,
        expire_on_commit=False,
    )
    with postgres_engine.begin() as connection:
        connection.execute(
            text("TRUNCATE alert_events, alerts, events RESTART IDENTITY CASCADE")
        )
    yield factory


def make_event(
    event_id: str,
    seconds: int = 0,
    *,
    source_record_id: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 9, 19, 10, 0, tzinfo=UTC)
        + timedelta(seconds=seconds),
        event_type=EventType.AUTHENTICATION_FAILURE,
        source="windows.security",
        source_record_id=source_record_id or event_id,
        username="marta.soler",
        source_ip="198.51.100.73",
        outcome=AuthenticationOutcome.FAILURE,
        host="DC-MAD-01",
        attributes={"event_code": 4625, "nested": {"safe": True}},
    )


def make_alert(event_ids: tuple[str, ...]) -> Alert:
    return Alert(
        alert_id="ea516fb3-1d13-5a49-bfad-7c4bbca3f826",
        timestamp=datetime(2026, 9, 19, 10, 0, tzinfo=UTC),
        rule_id="AUTH-BRUTEFORCE-001",
        title="Possible authentication brute force",
        severity=Severity.HIGH,
        username="marta.soler",
        source_ip="198.51.100.73",
        related_event_ids=event_ids,
        reason="5 failed authentications within 60 seconds",
    )


def test_migrations_created_expected_tables(postgres_engine: Engine) -> None:
    assert set(inspect(postgres_engine).get_table_names()) >= {
        "alembic_version",
        "events",
        "alerts",
        "alert_events",
    }


def test_event_repository_is_idempotent_and_round_trips_jsonb_and_inet(
    session_factory: SessionFactory,
) -> None:
    event = make_event("evt-1")

    with session_factory.begin() as session:
        repository = EventRepository(session)
        assert repository.add_many([event]) == 1
        assert repository.add_many([event]) == 0

    with session_factory() as session:
        restored = EventRepository(session).get(event.event_id)

    assert restored == event


def test_source_record_identity_prevents_duplicate_events(
    session_factory: SessionFactory,
) -> None:
    first = make_event("evt-1", source_record_id="same-source-record")
    second = make_event("evt-2", source_record_id="same-source-record")

    with session_factory.begin() as session:
        inserted = EventRepository(session).add_many([first, second])

    assert inserted == 1


def test_event_query_is_temporally_ordered(
    session_factory: SessionFactory,
) -> None:
    events = [make_event("evt-3", 30), make_event("evt-1"), make_event("evt-2", 15)]
    start = datetime(2026, 9, 19, 10, 0, tzinfo=UTC)

    with session_factory.begin() as session:
        repository = EventRepository(session)
        repository.add_many(events)
        restored = repository.list_between(start, start + timedelta(minutes=1))

    assert [event.event_id for event in restored] == ["evt-1", "evt-2", "evt-3"]


def test_alert_repository_preserves_evidence_and_is_idempotent(
    session_factory: SessionFactory,
) -> None:
    events = tuple(make_event(f"evt-{index}", index) for index in range(5))
    alert = make_alert(tuple(event.event_id for event in events))

    with session_factory.begin() as session:
        EventRepository(session).add_many(events)
        alerts = AlertRepository(session)
        assert alerts.add(alert) is True
        assert alerts.add(alert) is False

    with session_factory() as session:
        restored = AlertRepository(session).get(alert.alert_id)

    assert restored == alert


def test_missing_alert_evidence_rolls_back_transaction(
    session_factory: SessionFactory,
) -> None:
    alert = make_alert(("missing-event",))

    with pytest.raises(MissingRelatedEventsError):
        with session_factory.begin() as session:
            AlertRepository(session).add(alert)

    with session_factory() as session:
        assert AlertRepository(session).count() == 0


def test_exception_rolls_back_event_insert(
    session_factory: SessionFactory,
) -> None:
    with pytest.raises(RuntimeError, match="force rollback"):
        with session_factory.begin() as session:
            EventRepository(session).add_many([make_event("evt-rollback")])
            raise RuntimeError("force rollback")

    with session_factory() as session:
        assert EventRepository(session).count() == 0


@pytest.mark.parametrize(
    "raw_dataset",
    [
        Path("data/raw/windows_brute_force.jsonl"),
        Path("data/raw/linux_brute_force.jsonl"),
    ],
)
def test_raw_to_persisted_alert_pipeline_is_idempotent(
    raw_dataset: Path,
    tmp_path: Path,
    session_factory: SessionFactory,
) -> None:
    normalized = tmp_path / f"{raw_dataset.stem}.jsonl"
    run_normalization(raw_dataset, normalized)
    events = list(read_events(normalized))

    ingestion = EventIngestionService(session_factory)
    first_ingestion = ingestion.ingest(events)
    second_ingestion = ingestion.ingest(events)

    detection = DatabaseDetectionService(
        session_factory,
        detector_factory=lambda: [BruteForceDetector()],
    )
    first_detection = detection.detect(
        datetime(2026, 9, 19, 0, 0, tzinfo=UTC),
        datetime(2026, 9, 20, 0, 0, tzinfo=UTC),
    )
    second_detection = detection.detect(
        datetime(2026, 9, 19, 0, 0, tzinfo=UTC),
        datetime(2026, 9, 20, 0, 0, tzinfo=UTC),
    )

    assert first_ingestion.events_inserted == 5
    assert second_ingestion.duplicates == 5
    assert first_detection.alerts_inserted == 1
    assert second_detection.duplicates == 1
