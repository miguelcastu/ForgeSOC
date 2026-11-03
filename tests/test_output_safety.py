import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from forgesoc.detection.engine import DetectionEngine
from forgesoc.detection.registry import default_detectors
from forgesoc.domain.models import Alert
from forgesoc.ingestion.jsonl import read_events
from forgesoc.main import run
from forgesoc.output.jsonl import write_alerts


def interrupted_alerts() -> Iterator[Alert]:
    yield from DetectionEngine(default_detectors()).process(
        read_events(Path("data/security_events.jsonl"))
    )
    raise ValueError("invalid later record")


@pytest.mark.parametrize("existing", [False, True])
def test_failed_stream_does_not_publish_partial_output(
    tmp_path: Path, existing: bool
) -> None:
    output = tmp_path / "alerts.jsonl"
    if existing:
        output.write_text("previous complete report\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid later record"):
        write_alerts(interrupted_alerts(), output)

    if existing:
        assert output.read_text(encoding="utf-8") == "previous complete report\n"
    else:
        assert not output.exists()
    assert not list(tmp_path.glob(".*.tmp"))


def test_malformed_input_preserves_existing_output(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_text("not valid JSON\n", encoding="utf-8")
    output = tmp_path / "alerts.jsonl"
    output.write_text("previous complete report\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid event"):
        run(source, output)

    assert output.read_text(encoding="utf-8") == "previous complete report\n"


def test_input_cannot_be_used_as_output(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    original = Path("data/security_events.jsonl").read_bytes()
    source.write_bytes(original)

    with pytest.raises(ValueError, match="different files"):
        run(source, source)

    assert source.read_bytes() == original


def test_hardlinked_output_cannot_replace_input(tmp_path: Path) -> None:
    source = tmp_path / "events.jsonl"
    source.write_bytes(Path("data/security_events.jsonl").read_bytes())
    output = tmp_path / "alias.jsonl"
    try:
        os.link(source, output)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")

    with pytest.raises(ValueError, match="different files"):
        run(source, output)


def test_success_replaces_output_after_stream_completes(tmp_path: Path) -> None:
    output = tmp_path / "alerts.jsonl"
    output.write_text("old report\n", encoding="utf-8")
    assert run(Path("data/security_events.jsonl"), output) == 1
    records = [json.loads(line) for line in output.read_text().splitlines()]
    assert records[0]["rule_id"] == "AUTH-BRUTEFORCE-001"
    assert not list(tmp_path.glob(".*.tmp"))
