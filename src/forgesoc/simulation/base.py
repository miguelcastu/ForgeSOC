from collections.abc import Iterable
from typing import TYPE_CHECKING, Protocol

from forgesoc.domain.models import SecurityEvent

if TYPE_CHECKING:
    from forgesoc.simulation.generator import TelemetryGenerator


class Scenario(Protocol):
    @property
    def name(self) -> str:
        ...

    @property
    def description(self) -> str:
        ...

    def generate(
        self,
        generator: "TelemetryGenerator",
    ) -> Iterable[SecurityEvent]:
        ...
