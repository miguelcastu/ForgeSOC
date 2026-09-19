from typing import Protocol

from forgesoc.domain.models import Alert, SecurityEvent


class Detector(Protocol):
    def process(
        self,
        event: SecurityEvent,
    ) -> list[Alert]:
        ...