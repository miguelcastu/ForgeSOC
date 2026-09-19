import argparse
from datetime import UTC, datetime
from uuid import UUID

import pytest

from forgesoc.detection.brute_force import BruteForceDetector
from forgesoc.domain.models import (
    Alert,
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
    Severity,
)
from forgesoc.persistence.config import (
    DatabaseConfig,
    DatabaseConfigurationError,
)
from forgesoc.persistence.main import parse_timestamp
from forgesoc.persistence.mappers import (
    alert_from_row,
    alert_to_row,
    event_from_row,
    event_to_row,
)
from forgesoc.persistence.tables import AlertRow

TIMESTAMP = datetime(2026, 9, 19, 10, 0, tzinfo=UTC)


def make_event() -> SecurityEvent:
    return SecurityEvent(
        event_id="evt-persistence-001",
        timestamp=TIMESTAMP,
        event_type=EventType.AUTHENTICATION_FAILURE,
        source="windows.security",
        source_record_id="record-001",
        username="marta.soler",
        source_ip="198.51.100.73",
        outcome=AuthenticationOutcome.FAILURE,
        host="DC-MAD-01",
        attributes={"event_code": 4625, "nested": {"safe": True}},
    )


def make_alert() -> Alert:
    return Alert(
        alert_id="ea516fb3-1d13-5a49-bfad-7c4bbca3f826",
        timestamp=TIMESTAMP,
        rule_id="AUTH-BRUTEFORCE-001",
        title="Possible authentication brute force",
        severity=Severity.HIGH,
        username="marta.soler",
        source_ip="198.51.100.73",
        related_event_ids=("evt-1", "evt-2"),
        reason="5 failed authentications within 60 seconds",
    )


def test_database_config_requires_url() -> None:
    with pytest.raises(DatabaseConfigurationError, match="is required"):
        DatabaseConfig.from_environment({})


def test_database_config_rejects_non_postgresql_driver() -> None:
    with pytest.raises(DatabaseConfigurationError, match=r"postgresql\+psycopg"):
        DatabaseConfig.from_environment({"FORGESOC_DATABASE_URL": "sqlite:///x.db"})


def test_database_config_reads_echo_flag() -> None:
    config = DatabaseConfig.from_environment(
        {
            "FORGESOC_DATABASE_URL": "postgresql+psycopg://user:pass@db/test",
            "FORGESOC_DATABASE_ECHO": "true",
        }
    )

    assert config.echo is True


def test_database_cli_parses_utc_timestamp() -> None:
    assert parse_timestamp("2026-09-19T10:00:00Z") == TIMESTAMP


@pytest.mark.parametrize("value", ["not-a-date", "2026-09-19T10:00:00"])
def test_database_cli_rejects_invalid_or_naive_timestamp(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        parse_timestamp(value)


def test_event_mapper_round_trip() -> None:
    event = make_event()

    restored = event_from_row(event_to_row(event))

    assert restored == event


def test_alert_mapper_round_trip() -> None:
    alert = make_alert()
    row = alert_to_row(alert)

    restored = alert_from_row(row, alert.related_event_ids)

    assert restored == alert
    assert isinstance(row.alert_id, UUID)


def test_alert_mapper_rejects_invalid_uuid() -> None:
    alert = make_alert()
    invalid = Alert(
        alert_id="not-a-uuid",
        timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        title=alert.title,
        severity=alert.severity,
        username=alert.username,
        source_ip=alert.source_ip,
        related_event_ids=alert.related_event_ids,
        reason=alert.reason,
    )

    with pytest.raises(ValueError):
        alert_to_row(invalid)


def test_alert_id_is_deterministic_for_the_same_evidence() -> None:
    events = [
        SecurityEvent(
            event_id=f"evt-{index}",
            timestamp=TIMESTAMP,
            event_type=EventType.AUTHENTICATION_FAILURE,
            source="test",
            username="marta.soler",
            source_ip="198.51.100.73",
            outcome=AuthenticationOutcome.FAILURE,
        )
        for index in range(5)
    ]

    first = BruteForceDetector()
    second = BruteForceDetector()
    first_alerts = [alert for event in events for alert in first.process(event)]
    second_alerts = [alert for event in events for alert in second.process(event)]

    assert first_alerts[0].alert_id == second_alerts[0].alert_id


def test_table_metadata_contains_expected_tables() -> None:
    assert AlertRow.metadata.tables.keys() >= {
        "events",
        "alerts",
        "alert_events",
    }
