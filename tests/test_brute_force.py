from datetime import UTC, datetime, timedelta

from forgesoc.detection.brute_force import BruteForceDetector
from forgesoc.domain.models import (
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
)

BASE_TIME = datetime(2026, 9, 19, 10, 0, tzinfo=UTC)


def make_event(
    event_id: str,
    seconds: int,
    username: str = "mike",
    source_ip: str = "185.10.10.50",
    outcome: AuthenticationOutcome = AuthenticationOutcome.FAILURE,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        event_type=EventType.AUTHENTICATION,
        source="vpn",
        username=username,
        source_ip=source_ip,
        outcome=outcome,
    )


def test_generates_alert_after_five_failures() -> None:
    detector = BruteForceDetector()
    alerts = []

    for index in range(5):
        alerts.extend(detector.process(make_event(f"evt-{index}", index * 10)))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "AUTH-BRUTEFORCE-001"
    assert alert.username == "mike"
    assert alert.source_ip == "185.10.10.50"
    assert alert.related_event_ids == tuple(f"evt-{index}" for index in range(5))


def test_four_failures_do_not_generate_alert() -> None:
    detector = BruteForceDetector()
    alerts = []

    for index in range(4):
        alerts.extend(detector.process(make_event(f"evt-{index}", index * 10)))

    assert alerts == []


def test_different_users_are_not_mixed() -> None:
    detector = BruteForceDetector()
    alerts = []
    users = ["mike", "alice", "john", "sarah", "bob"]

    for index, user in enumerate(users):
        alerts.extend(
            detector.process(make_event(f"evt-{index}", index * 10, username=user))
        )

    assert alerts == []


def test_successful_login_resets_failures() -> None:
    detector = BruteForceDetector()

    for index in range(4):
        detector.process(make_event(f"failure-{index}", index * 5))

    detector.process(
        make_event("success", 25, outcome=AuthenticationOutcome.SUCCESS)
    )

    alerts = []
    for index in range(4):
        alerts.extend(
            detector.process(make_event(f"new-failure-{index}", 30 + index * 5))
        )

    assert alerts == []


def test_failures_outside_time_window_do_not_trigger() -> None:
    detector = BruteForceDetector()
    alerts = []

    for index, seconds in enumerate([0, 30, 70, 100, 140]):
        alerts.extend(detector.process(make_event(f"evt-{index}", seconds)))

    assert alerts == []


def test_detector_does_not_spam_duplicate_alerts() -> None:
    detector = BruteForceDetector()
    alerts = []

    for index in range(8):
        alerts.extend(detector.process(make_event(f"evt-{index}", index * 5)))

    assert len(alerts) == 1


def test_same_evidence_generates_same_alert_id() -> None:
    first_detector = BruteForceDetector()
    second_detector = BruteForceDetector()
    events = [make_event(f"evt-{index}", index * 5) for index in range(5)]

    first_alerts = [
        alert for event in events for alert in first_detector.process(event)
    ]
    second_alerts = [
        alert for event in events for alert in second_detector.process(event)
    ]

    assert first_alerts[0].alert_id == second_alerts[0].alert_id
