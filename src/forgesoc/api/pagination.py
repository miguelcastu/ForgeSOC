import base64
import json
from datetime import datetime


class InvalidCursorError(ValueError):
    """Raised when an API pagination cursor cannot be decoded."""


def encode_cursor(timestamp: datetime, identifier: str) -> str:
    payload = json.dumps(
        {"timestamp": timestamp.isoformat(), "id": identifier},
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_cursor(value: str | None) -> tuple[datetime | None, str | None]:
    if value is None:
        return None, None
    try:
        padding = "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(value + padding))
        timestamp = datetime.fromisoformat(payload["timestamp"])
        identifier = payload["id"]
        if timestamp.tzinfo is None or not isinstance(identifier, str):
            raise ValueError
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise InvalidCursorError("invalid pagination cursor") from exc
    return timestamp, identifier
