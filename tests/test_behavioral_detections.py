from datetime import UTC, datetime

import pytest

from forgesoc.detection.engine import DetectionEngine
from forgesoc.detection.registry import default_detectors, detection_catalog
from forgesoc.simulation.generator import TelemetryGenerator
from forgesoc.simulation.scenarios import get_scenario

START = datetime(2026, 9, 20, 10, 0, tzinfo=UTC)


def detect_scenario(name: str) -> set[str]:
    scenario = get_scenario(name)
    events = scenario.generate(TelemetryGenerator(name, 42, START))
    return {
        alert.rule_id for alert in DetectionEngine(default_detectors()).process(events)
    }


@pytest.mark.parametrize(
    ("scenario", "expected_rule"),
    [
        ("brute-force", "AUTH-BRUTEFORCE-001"),
        ("credential-spraying", "AUTH-SPRAY-002"),
        ("suspicious-powershell", "WIN-POWERSHELL-003"),
        ("windows-credential-dumping", "OS-CREDDUMP-004"),
        ("linux-privilege-escalation", "LNX-SUDO-005"),
        ("windows-service-persistence", "OS-SERVICE-006"),
        ("linux-service-persistence", "OS-SERVICE-006"),
        ("dns-beaconing", "NET-DNS-BEACON-007"),
    ],
)
def test_attack_scenario_generates_expected_detection(
    scenario: str, expected_rule: str
) -> None:
    assert expected_rule in detect_scenario(scenario)


def test_normal_activity_has_no_alerts() -> None:
    assert detect_scenario("normal-activity") == set()


def test_detection_catalog_has_unique_rules_and_complete_mitre_metadata() -> None:
    catalog = detection_catalog()

    assert len({item.rule_id for item in catalog}) == len(catalog)
    assert all(
        item.log_types and item.event_types and item.platforms for item in catalog
    )
    assert all(
        technique.technique_id.startswith("T") and technique.url.startswith("https://")
        for item in catalog
        for technique in item.mitre
    )
