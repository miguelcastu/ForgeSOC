from collections.abc import Callable, Iterable
from datetime import datetime

from forgesoc.detection.base import Detector
from forgesoc.detection.engine import DetectionEngine
from forgesoc.domain.models import SecurityEvent
from forgesoc.persistence.database import SessionFactory
from forgesoc.persistence.models import (
    DatabaseStats,
    DetectionSummary,
    IngestionSummary,
)
from forgesoc.persistence.repositories import AlertRepository, EventRepository

type DetectorFactory = Callable[[], Iterable[Detector]]


class EventIngestionService:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def ingest(self, events: Iterable[SecurityEvent]) -> IngestionSummary:
        event_list = list(events)

        with self._session_factory.begin() as session:
            inserted = EventRepository(session).add_many(event_list)

        return IngestionSummary(
            events_received=len(event_list),
            events_inserted=inserted,
            duplicates=len(event_list) - inserted,
        )


class DatabaseDetectionService:
    def __init__(
        self,
        session_factory: SessionFactory,
        detector_factory: DetectorFactory,
    ) -> None:
        self._session_factory = session_factory
        self._detector_factory = detector_factory

    def detect(self, start: datetime, end: datetime) -> DetectionSummary:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("detection range must include timezones")
        if start >= end:
            raise ValueError("detection start must be earlier than end")

        with self._session_factory.begin() as session:
            events = EventRepository(session).list_between(start, end)
            engine = DetectionEngine(self._detector_factory())
            alerts = list(engine.process(events))
            inserted = AlertRepository(session).add_many(alerts)

        return DetectionSummary(
            events_processed=len(events),
            alerts_generated=len(alerts),
            alerts_inserted=inserted,
            duplicates=len(alerts) - inserted,
        )


class DatabaseStatsService:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def get(self) -> DatabaseStats:
        with self._session_factory() as session:
            events = EventRepository(session)
            alerts = AlertRepository(session)
            return DatabaseStats(
                events=events.count(),
                alerts=alerts.count(),
                events_by_source=events.counts_by_source(),
                events_by_type=events.counts_by_type(),
                alerts_by_severity=alerts.counts_by_severity(),
                alerts_by_rule=alerts.counts_by_rule(),
            )
