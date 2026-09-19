from hashlib import sha256
from typing import Protocol

from forgesoc.domain.models import SecurityEvent
from forgesoc.normalization.schemas import RawEventEnvelope


class UnsupportedEventError(ValueError):
    """Raised when a valid source record describes an unsupported activity."""


class Normalizer(Protocol):
    source_type: str

    def normalize(self, envelope: RawEventEnvelope) -> SecurityEvent:
        ...


def stable_event_id(source_type: str, source_record_id: str) -> str:
    identity = f"{source_type}\0{source_record_id}".encode()
    return f"evt-{sha256(identity).hexdigest()[:24]}"
