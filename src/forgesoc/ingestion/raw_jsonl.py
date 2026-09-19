from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RawRecord:
    input_path: Path
    line_number: int
    raw_text: str


def read_raw_records(path: Path) -> Iterator[RawRecord]:
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            raw_text = line.strip()

            if not raw_text:
                continue

            yield RawRecord(
                input_path=path,
                line_number=line_number,
                raw_text=raw_text,
            )
