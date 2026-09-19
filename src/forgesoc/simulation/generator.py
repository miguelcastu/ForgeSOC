import random
from collections.abc import Sequence
from datetime import datetime, timedelta

from forgesoc.domain.models import (
    AuthenticationOutcome,
    EventType,
    JsonValue,
    SecurityEvent,
)


class TelemetryGenerator:
    """Build deterministic security events for one named scenario."""

    def __init__(
        self,
        scenario_name: str,
        seed: int,
        start_time: datetime,
    ) -> None:
        if start_time.tzinfo is None:
            raise ValueError("start_time must include a timezone")

        self._scenario_name = scenario_name
        self._random = random.Random(seed)
        self._current_time = start_time
        self._sequence = 0

    def choice(self, values: Sequence[str]) -> str:
        return self._random.choice(values)

    def event(
        self,
        event_type: EventType,
        source: str,
        *,
        after_seconds: int = 0,
        username: str | None = None,
        source_ip: str | None = None,
        outcome: AuthenticationOutcome | None = None,
        host: str | None = None,
        attributes: dict[str, JsonValue] | None = None,
    ) -> SecurityEvent:
        if after_seconds < 0:
            raise ValueError("after_seconds cannot be negative")

        self._current_time += timedelta(seconds=after_seconds)
        self._sequence += 1

        return SecurityEvent(
            event_id=f"{self._scenario_name}-{self._sequence:04d}",
            timestamp=self._current_time,
            event_type=event_type,
            source=source,
            username=username,
            source_ip=source_ip,
            outcome=outcome,
            host=host,
            attributes=attributes or {},
        )
