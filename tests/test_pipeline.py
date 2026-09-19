import json
from pathlib import Path

from forgesoc.main import run


def test_pipeline_writes_brute_force_alert(tmp_path: Path) -> None:
    input_path = Path("data/security_events.jsonl")
    output_path = tmp_path / "alerts.jsonl"

    alert_count = run(input_path, output_path)

    records = [json.loads(line) for line in output_path.read_text().splitlines()]
    assert alert_count == 1
    assert len(records) == 1
    assert records[0]["rule_id"] == "AUTH-BRUTEFORCE-001"
    assert records[0]["severity"] == "high"
    assert records[0]["related_event_ids"] == [
        "evt-001",
        "evt-002",
        "evt-003",
        "evt-004",
        "evt-005",
    ]
