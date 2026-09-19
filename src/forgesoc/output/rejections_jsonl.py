import json
from collections.abc import Iterable
from pathlib import Path

from forgesoc.normalization.models import NormalizationFailure


def write_rejections(
    failures: Iterable[NormalizationFailure],
    path: Path,
    *,
    overwrite: bool = False,
) -> int:
    if path.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {path}")

    path.parent.mkdir(parents=True, exist_ok=True)
    rejection_count = 0

    with path.open("w", encoding="utf-8", newline="\n") as file:
        for failure in failures:
            record = {
                "input_path": str(failure.input_path),
                "line_number": failure.line_number,
                "source_type": failure.source_type,
                "source_record_id": failure.source_record_id,
                "error_code": failure.error_code.value,
                "message": failure.message,
            }
            file.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            file.write("\n")
            rejection_count += 1

    return rejection_count
