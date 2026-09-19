import json
from collections.abc import Iterable, Iterator

from pydantic import ValidationError

from forgesoc.ingestion.raw_jsonl import RawRecord
from forgesoc.normalization.base import Normalizer, UnsupportedEventError
from forgesoc.normalization.models import (
    NormalizationError,
    NormalizationErrorCode,
    NormalizationFailure,
    NormalizationResult,
    NormalizationSuccess,
)
from forgesoc.normalization.schemas import RawEventEnvelope


class NormalizationEngine:
    def __init__(self, normalizers: Iterable[Normalizer]) -> None:
        self._normalizers: dict[str, Normalizer] = {}

        for normalizer in normalizers:
            if normalizer.source_type in self._normalizers:
                raise ValueError(
                    f"Duplicate normalizer for source {normalizer.source_type!r}"
                )
            self._normalizers[normalizer.source_type] = normalizer

    @property
    def source_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._normalizers))

    def normalize(
        self,
        records: Iterable[RawRecord],
        *,
        continue_on_error: bool = False,
    ) -> Iterator[NormalizationResult]:
        for record in records:
            result = self._normalize_record(record)

            if isinstance(result, NormalizationFailure) and not continue_on_error:
                raise NormalizationError(result)

            yield result

    def _normalize_record(self, record: RawRecord) -> NormalizationResult:
        try:
            raw_data = json.loads(record.raw_text)
        except json.JSONDecodeError as exc:
            return self._failure(
                record,
                NormalizationErrorCode.INVALID_JSON,
                f"{exc.msg} at column {exc.colno}",
            )

        if not isinstance(raw_data, dict):
            return self._failure(
                record,
                NormalizationErrorCode.INVALID_RECORD,
                "each JSONL line must contain an object",
            )

        source_type = self._optional_string(raw_data.get("source_type"))
        source_record_id = self._optional_string(raw_data.get("record_id"))

        try:
            envelope = RawEventEnvelope.model_validate(raw_data)
        except ValidationError as exc:
            return self._validation_failure(
                record,
                exc,
                source_type=source_type,
                source_record_id=source_record_id,
            )

        normalizer = self._normalizers.get(envelope.source_type)
        if normalizer is None:
            return self._failure(
                record,
                NormalizationErrorCode.UNSUPPORTED_SOURCE,
                f"no normalizer registered for {envelope.source_type!r}",
                source_type=envelope.source_type,
                source_record_id=envelope.record_id,
            )

        try:
            event = normalizer.normalize(envelope)
        except ValidationError as exc:
            return self._validation_failure(
                record,
                exc,
                source_type=envelope.source_type,
                source_record_id=envelope.record_id,
            )
        except UnsupportedEventError as exc:
            return self._failure(
                record,
                NormalizationErrorCode.UNSUPPORTED_EVENT,
                str(exc),
                source_type=envelope.source_type,
                source_record_id=envelope.record_id,
            )

        return NormalizationSuccess(
            source_type=envelope.source_type,
            source_record_id=envelope.record_id,
            event=event,
        )

    def _validation_failure(
        self,
        record: RawRecord,
        error: ValidationError,
        *,
        source_type: str | None,
        source_record_id: str | None,
    ) -> NormalizationFailure:
        details = error.errors(include_url=False)
        error_code = (
            NormalizationErrorCode.MISSING_FIELD
            if any(detail["type"] == "missing" for detail in details)
            else NormalizationErrorCode.INVALID_FIELD
        )
        messages = []

        for detail in details:
            location = ".".join(str(part) for part in detail["loc"])
            messages.append(f"{location}: {detail['msg']}")

        return self._failure(
            record,
            error_code,
            "; ".join(messages),
            source_type=source_type,
            source_record_id=source_record_id,
        )

    @staticmethod
    def _failure(
        record: RawRecord,
        error_code: NormalizationErrorCode,
        message: str,
        *,
        source_type: str | None = None,
        source_record_id: str | None = None,
    ) -> NormalizationFailure:
        return NormalizationFailure(
            input_path=record.input_path,
            line_number=record.line_number,
            source_type=source_type,
            source_record_id=source_record_id,
            error_code=error_code,
            message=message,
        )

    @staticmethod
    def _optional_string(value: object) -> str | None:
        return value if isinstance(value, str) else None
