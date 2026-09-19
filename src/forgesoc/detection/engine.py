from collections.abc import (
    Iterable,
    Iterator,
)

from forgesoc.detection.base import Detector
from forgesoc.domain.models import (
    Alert,
    SecurityEvent,
)


class DetectionEngine:
    def __init__(
        self,
        detectors: Iterable[Detector],
    ) -> None:
        self._detectors = list(detectors)

    def process(
        self,
        events: Iterable[SecurityEvent],
    ) -> Iterator[Alert]:
        for event in events:
            for detector in self._detectors:
                yield from detector.process(event)