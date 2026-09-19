import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from forgesoc.domain.models import (
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
)


def read_events(path: Path) -> Iterator[SecurityEvent]:
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)

                yield SecurityEvent(
                    event_id=data["event_id"],
                    timestamp=datetime.fromisoformat(data["timestamp"]),
                    event_type=EventType(data["event_type"]),
                    source=data["source"],
                    username=data.get("username"),
                    source_ip=data.get("source_ip"),
                    outcome=(
                        AuthenticationOutcome(data["outcome"])
                        if data.get("outcome") is not None
                        else None
                    ),
                )

            except (
                KeyError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise ValueError(
                    f"Invalid event at line {line_number}: {exc}"
                ) from exc