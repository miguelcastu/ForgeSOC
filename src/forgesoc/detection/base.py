from typing import Protocol

from forgesoc.detection.catalog import DetectionMetadata
from forgesoc.domain.models import Alert, SecurityEvent


class Detector(Protocol):
    metadata: DetectionMetadata

    def process(
        self,
        event: SecurityEvent,
    ) -> list[Alert]: ...
