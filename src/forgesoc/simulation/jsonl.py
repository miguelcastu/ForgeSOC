import json
from collections.abc import Iterable
from pathlib import Path

from forgesoc.domain.models import SecurityEvent


def event_to_record(event: SecurityEvent) -> dict[str, object]:
    record: dict[str, object] = {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type.value,
        "source": event.source,
    }

    optional_fields = {
        "username": event.username,
        "source_ip": event.source_ip,
        "outcome": event.outcome.value if event.outcome is not None else None,
        "host": event.host,
    }
    record.update({key: value for key, value in optional_fields.items() if value})

    if event.attributes:
        record["attributes"] = dict(event.attributes)

    return record


def write_events(
    events: Iterable[SecurityEvent],
    path: Path,
    *,
    overwrite: bool = False,
) -> int:
    if path.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {path}")

    path.parent.mkdir(parents=True, exist_ok=True)
    event_count = 0

    with path.open("w", encoding="utf-8", newline="\n") as file:
        for event in events:
            file.write(
                json.dumps(
                    event_to_record(event),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            file.write("\n")
            event_count += 1

    return event_count
