from datetime import UTC, datetime
from pathlib import Path

import pytest

from forgesoc.detection.brute_force import BruteForceDetector
from forgesoc.detection.engine import DetectionEngine
from forgesoc.domain.models import AuthenticationOutcome, EventType, SecurityEvent
from forgesoc.ingestion.jsonl import read_events
from forgesoc.simulation.generator import TelemetryGenerator
from forgesoc.simulation.jsonl import write_events
from forgesoc.simulation.main import run_generation
from forgesoc.simulation.scenarios import SCENARIOS, get_scenario

START_TIME = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


def generate(name: str, seed: int = 42) -> list[SecurityEvent]:
    scenario = get_scenario(name)
    generator = TelemetryGenerator(name, seed, START_TIME)
    return list(scenario.generate(generator))


@pytest.mark.parametrize(
    ("scenario_name", "expected_count"),
    [
        ("normal-activity", 7),
        ("brute-force", 6),
        ("brute-force-then-success", 6),
        ("suspicious-powershell", 2),
        ("malicious-domain", 3),
        ("credential-spraying", 8),
        ("windows-credential-dumping", 1),
        ("linux-privilege-escalation", 2),
        ("windows-service-persistence", 1),
        ("linux-service-persistence", 1),
        ("dns-beaconing", 6),
    ],
)
def test_scenarios_generate_ordered_unique_events(
    scenario_name: str,
    expected_count: int,
) -> None:
    events = generate(scenario_name)

    assert len(events) == expected_count
    assert len({event.event_id for event in events}) == expected_count
    assert [event.timestamp for event in events] == sorted(
        event.timestamp for event in events
    )
    assert all(event.timestamp.tzinfo is not None for event in events)


def test_generation_is_deterministic() -> None:
    assert generate("normal-activity", seed=73) == generate("normal-activity", seed=73)


def test_same_inputs_create_byte_identical_datasets(tmp_path: Path) -> None:
    first_path = tmp_path / "first.jsonl"
    second_path = tmp_path / "second.jsonl"

    run_generation("normal-activity", first_path, seed=73)
    run_generation("normal-activity", second_path, seed=73)

    assert first_path.read_bytes() == second_path.read_bytes()


def test_scenarios_cover_all_planned_event_types() -> None:
    generated_types = {
        event.event_type
        for scenario_name in SCENARIOS
        for event in generate(scenario_name)
    }

    assert generated_types == {
        EventType.AUTHENTICATION_SUCCESS,
        EventType.AUTHENTICATION_FAILURE,
        EventType.PROCESS_START,
        EventType.NETWORK_CONNECTION,
        EventType.DNS_QUERY,
        EventType.HTTP_REQUEST,
        EventType.PRIVILEGE_USE,
        EventType.SERVICE_INSTALL,
        EventType.FILE_CHANGE,
    }


@pytest.mark.parametrize(
    ("scenario_name", "expected_alerts"),
    [
        ("normal-activity", 0),
        ("brute-force", 1),
        ("brute-force-then-success", 1),
        ("credential-spraying", 0),
        ("suspicious-powershell", 0),
        ("malicious-domain", 0),
    ],
)
def test_scenarios_have_expected_current_detection_results(
    scenario_name: str,
    expected_alerts: int,
) -> None:
    engine = DetectionEngine([BruteForceDetector()])

    alerts = list(engine.process(generate(scenario_name)))

    assert len(alerts) == expected_alerts


def test_brute_force_then_success_ends_with_success() -> None:
    events = generate("brute-force-then-success")

    assert events[-1].event_type == EventType.AUTHENTICATION_SUCCESS
    assert events[-1].outcome == AuthenticationOutcome.SUCCESS
    assert events[-1].username == events[0].username
    assert events[-1].source_ip == events[0].source_ip


def test_credential_spraying_uses_one_ip_and_different_users() -> None:
    events = generate("credential-spraying")

    assert len({event.source_ip for event in events}) == 1
    assert len({event.username for event in events}) == len(events)


def test_malicious_domain_events_share_correlation_id() -> None:
    events = generate("malicious-domain")

    assert [event.event_type for event in events] == [
        EventType.DNS_QUERY,
        EventType.NETWORK_CONNECTION,
        EventType.HTTP_REQUEST,
    ]
    assert {event.attributes["correlation_id"] for event in events} == {
        "synthetic-domain-chain-001"
    }


def test_suspicious_powershell_has_expected_indicators() -> None:
    events = generate("suspicious-powershell")
    powershell = events[-1]

    assert powershell.attributes["process_name"] == "powershell.exe"
    assert powershell.attributes["parent_process"] == "WINWORD.EXE"
    assert "-EncodedCommand" in str(powershell.attributes["command_line"])


def test_generated_jsonl_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "brute-force.jsonl"
    original_events = generate("brute-force")

    count = write_events(original_events, path)
    loaded_events = list(read_events(path))

    assert count == len(original_events)
    assert loaded_events == original_events


def test_writer_protects_existing_dataset(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("do not replace", encoding="utf-8")

    with pytest.raises(FileExistsError, match="Output already exists"):
        write_events(generate("normal-activity"), path)

    assert path.read_text(encoding="utf-8") == "do not replace"


def test_generation_command_creates_nested_output_directory(tmp_path: Path) -> None:
    output_path = tmp_path / "generated" / "spray.jsonl"

    count = run_generation("credential-spraying", output_path, seed=19)

    assert count == 8
    assert len(list(read_events(output_path))) == 8
