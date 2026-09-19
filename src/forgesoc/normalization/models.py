from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from forgesoc.domain.models import SecurityEvent


class NormalizationErrorCode(StrEnum):
    INVALID_JSON = "invalid_json"
    INVALID_RECORD = "invalid_record"
    MISSING_FIELD = "missing_field"
    INVALID_FIELD = "invalid_field"
    UNSUPPORTED_SOURCE = "unsupported_source"
    UNSUPPORTED_EVENT = "unsupported_event"


@dataclass(frozen=True, slots=True)
class NormalizationSuccess:
    source_type: str
    source_record_id: str
    event: SecurityEvent


@dataclass(frozen=True, slots=True)
class NormalizationFailure:
    input_path: Path
    line_number: int
    source_type: str | None
    source_record_id: str | None
    error_code: NormalizationErrorCode
    message: str


type NormalizationResult = NormalizationSuccess | NormalizationFailure


class NormalizationError(ValueError):
    def __init__(self, failure: NormalizationFailure) -> None:
        self.failure = failure
        super().__init__(
            f"{failure.input_path}:{failure.line_number}: "
            f"{failure.error_code.value}: {failure.message}"
        )


@dataclass(frozen=True, slots=True)
class NormalizationReport:
    records_read: int
    events_normalized: int
    events_rejected: int
    by_source: Mapping[str, int]
    by_event_type: Mapping[str, int]
    by_error_code: Mapping[str, int]

    @classmethod
    def from_results(
        cls,
        results: Iterable[NormalizationResult],
    ) -> "NormalizationReport":
        records_read = 0
        events_normalized = 0
        events_rejected = 0
        by_source: Counter[str] = Counter()
        by_event_type: Counter[str] = Counter()
        by_error_code: Counter[str] = Counter()

        for result in results:
            records_read += 1
            source_type = result.source_type or "unknown"
            by_source[source_type] += 1

            if isinstance(result, NormalizationSuccess):
                events_normalized += 1
                by_event_type[result.event.event_type.value] += 1
            else:
                events_rejected += 1
                by_error_code[result.error_code.value] += 1

        return cls(
            records_read=records_read,
            events_normalized=events_normalized,
            events_rejected=events_rejected,
            by_source=dict(sorted(by_source.items())),
            by_event_type=dict(sorted(by_event_type.items())),
            by_error_code=dict(sorted(by_error_code.items())),
        )
