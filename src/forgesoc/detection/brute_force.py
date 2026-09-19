from collections import defaultdict, deque
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

from forgesoc.domain.models import (
    Alert,
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
    Severity,
)


class BruteForceDetector:
    RULE_ID = "AUTH-BRUTEFORCE-001"
    RULE_TITLE = "Possible authentication brute force"
    AUTHENTICATION_EVENT_TYPES = {
        EventType.AUTHENTICATION,
        EventType.AUTHENTICATION_SUCCESS,
        EventType.AUTHENTICATION_FAILURE,
    }

    def __init__(
        self,
        threshold: int = 5,
        window: timedelta = timedelta(seconds=60),
    ) -> None:
        self.threshold = threshold
        self.window = window
        self._failures: dict[tuple[str, str], deque[SecurityEvent]] = defaultdict(
            deque
        )
        self._alerted_keys: set[tuple[str, str]] = set()

    def process(self, event: SecurityEvent) -> list[Alert]:
        if event.event_type not in self.AUTHENTICATION_EVENT_TYPES:
            return []

        if event.username is None or event.source_ip is None:
            return []

        key = (event.username, event.source_ip)

        if event.outcome == AuthenticationOutcome.SUCCESS:
            self._reset(key)
            return []

        if event.outcome != AuthenticationOutcome.FAILURE:
            return []

        failures = self._failures[key]
        self._remove_expired_events(failures, event)

        if len(failures) < self.threshold:
            self._alerted_keys.discard(key)

        failures.append(event)

        if len(failures) >= self.threshold and key not in self._alerted_keys:
            self._alerted_keys.add(key)
            return [self._create_alert(event, failures)]

        return []

    def _remove_expired_events(
        self,
        failures: deque[SecurityEvent],
        current_event: SecurityEvent,
    ) -> None:
        cutoff = current_event.timestamp - self.window

        while failures and failures[0].timestamp < cutoff:
            failures.popleft()

    def _reset(self, key: tuple[str, str]) -> None:
        self._failures.pop(key, None)
        self._alerted_keys.discard(key)

    def _create_alert(
        self,
        triggering_event: SecurityEvent,
        failures: deque[SecurityEvent],
    ) -> Alert:
        related_event_ids = tuple(event.event_id for event in failures)
        alert_identity = "\0".join((self.RULE_ID, *related_event_ids))

        return Alert(
            alert_id=str(uuid5(NAMESPACE_URL, alert_identity)),
            timestamp=triggering_event.timestamp,
            rule_id=self.RULE_ID,
            title=self.RULE_TITLE,
            severity=Severity.HIGH,
            username=triggering_event.username,
            source_ip=triggering_event.source_ip,
            related_event_ids=related_event_ids,
            reason=(
                f"{len(failures)} failed authentications within "
                f"{self.window.total_seconds():.0f} seconds"
            ),
        )
