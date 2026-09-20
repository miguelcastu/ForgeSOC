import json
from datetime import UTC
from pathlib import Path

import pytest

from forgesoc.domain.models import (
    AuthenticationOutcome,
    EventType,
)
from forgesoc.ingestion.jsonl import read_events
from forgesoc.ingestion.raw_jsonl import RawRecord, read_raw_records
from forgesoc.main import run as run_detection
from forgesoc.normalization.engine import NormalizationEngine
from forgesoc.normalization.main import build_engine, run_normalization
from forgesoc.normalization.models import (
    NormalizationError,
    NormalizationErrorCode,
    NormalizationFailure,
    NormalizationSuccess,
)
from forgesoc.normalization.windows_parser import WindowsAuthenticationNormalizer


def windows_envelope(
    *,
    record_id: str = "win-1001",
    event_code: int = 4625,
    source_ip: str = "198.51.100.73",
) -> dict[str, object]:
    return {
        "source_type": "windows.security",
        "record_id": record_id,
        "payload": {
            "EventID": event_code,
            "TimeCreated": "2026-09-19T12:00:00+02:00",
            "Computer": "DC-MAD-01",
            "TargetUserName": "marta.soler",
            "IpAddress": source_ip,
            "LogonType": 10,
            "AuthenticationPackageName": "Negotiate",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
        },
    }


def linux_envelope(
    *,
    record_id: str = "ssh-2001",
    result: str = "failed",
) -> dict[str, object]:
    return {
        "source_type": "linux.ssh",
        "record_id": record_id,
        "payload": {
            "timestamp": "2026-09-19T10:00:00Z",
            "hostname": "lnx-jump-01",
            "program": "sshd",
            "user": "marta.soler",
            "remote_addr": "198.51.100.73",
            "remote_port": 50101,
            "result": result,
            "authentication_method": "password",
            "message": f"SSH authentication {result}",
        },
    }


def sysmon_envelope(event_code: int = 1) -> dict[str, object]:
    payload: dict[str, object] = {
        "EventID": event_code,
        "UtcTime": "2026-09-20T10:00:00Z",
        "Computer": "WS-FIN-021",
        "User": "marta.soler",
        "Image": "powershell.exe",
    }
    if event_code == 1:
        payload.update(
            {
                "CommandLine": "powershell.exe -EncodedCommand U3ludGhldGlj",
                "ParentImage": "WINWORD.EXE",
            }
        )
    elif event_code == 22:
        payload["QueryName"] = "cdn-security-update.test"
    return {
        "source_type": "windows.sysmon",
        "record_id": "sysmon-1",
        "payload": payload,
    }


def auditd_envelope(record_type: str = "USER_CMD") -> dict[str, object]:
    payload: dict[str, object] = {
        "timestamp": "2026-09-20T10:00:00Z",
        "hostname": "lnx-jump-01",
        "record_type": record_type,
        "user": "marta.soler",
    }
    if record_type == "USER_CMD":
        payload.update({"command_line": "sudo /bin/bash", "target_user": "root"})
    elif record_type == "PATH":
        payload.update({"path": "/etc/cron.d/update", "action": "created"})
    return {"source_type": "linux.auditd", "record_id": "audit-1", "payload": payload}


def raw_record(data: object, line_number: int = 1) -> RawRecord:
    return RawRecord(
        input_path=Path("synthetic.jsonl"),
        line_number=line_number,
        raw_text=json.dumps(data),
    )


def normalize_one(data: object) -> NormalizationSuccess:
    results = list(build_engine().normalize([raw_record(data)], continue_on_error=True))
    assert len(results) == 1
    result = results[0]
    assert isinstance(result, NormalizationSuccess)
    return result


def test_windows_failure_maps_to_canonical_event_in_utc() -> None:
    event = normalize_one(windows_envelope()).event

    assert event.event_type == EventType.AUTHENTICATION_FAILURE
    assert event.outcome == AuthenticationOutcome.FAILURE
    assert event.username == "marta.soler"
    assert event.source_ip == "198.51.100.73"
    assert event.host == "DC-MAD-01"
    assert event.timestamp.tzinfo == UTC
    assert event.timestamp.hour == 10
    assert event.source == "windows.security"
    assert event.source_record_id == "win-1001"
    assert event.schema_version == "1.0.0"
    assert event.attributes["event_code"] == 4625


def test_windows_success_maps_to_canonical_success() -> None:
    event = normalize_one(windows_envelope(event_code=4624)).event

    assert event.event_type == EventType.AUTHENTICATION_SUCCESS
    assert event.outcome == AuthenticationOutcome.SUCCESS


def test_linux_failure_maps_to_same_canonical_semantics() -> None:
    windows_event = normalize_one(windows_envelope()).event
    linux_event = normalize_one(linux_envelope()).event

    assert linux_event.event_type == windows_event.event_type
    assert linux_event.outcome == windows_event.outcome
    assert linux_event.username == windows_event.username
    assert linux_event.source_ip == windows_event.source_ip
    assert linux_event.timestamp == windows_event.timestamp
    assert linux_event.attributes["service"] == "sshd"


def test_linux_success_maps_to_canonical_success() -> None:
    event = normalize_one(linux_envelope(result="accepted")).event

    assert event.event_type == EventType.AUTHENTICATION_SUCCESS
    assert event.outcome == AuthenticationOutcome.SUCCESS


def test_sysmon_process_and_dns_events_are_normalized() -> None:
    process = normalize_one(sysmon_envelope()).event
    dns = normalize_one(sysmon_envelope(22)).event

    assert process.event_type == EventType.PROCESS_START
    assert process.attributes["parent_process"] == "WINWORD.EXE"
    assert dns.event_type == EventType.DNS_QUERY
    assert dns.attributes["query"] == "cdn-security-update.test"


def test_linux_audit_privilege_and_file_events_are_normalized() -> None:
    privilege = normalize_one(auditd_envelope()).event
    file_change = normalize_one(auditd_envelope("PATH")).event

    assert privilege.event_type == EventType.PRIVILEGE_USE
    assert privilege.attributes["target_user"] == "root"
    assert file_change.event_type == EventType.FILE_CHANGE
    assert file_change.attributes["path"] == "/etc/cron.d/update"


def test_event_identity_is_stable_and_source_scoped() -> None:
    first = normalize_one(windows_envelope()).event
    repeated = normalize_one(windows_envelope()).event
    different_record = normalize_one(windows_envelope(record_id="win-1002")).event
    different_source = normalize_one(linux_envelope(record_id="win-1001")).event

    assert first.event_id == repeated.event_id
    assert first.event_id != different_record.event_id
    assert first.event_id != different_source.event_id


@pytest.mark.parametrize(
    ("raw_text", "expected_code"),
    [
        ("{broken", NormalizationErrorCode.INVALID_JSON),
        ("[]", NormalizationErrorCode.INVALID_RECORD),
        (
            json.dumps({"record_id": "missing-source", "payload": {}}),
            NormalizationErrorCode.MISSING_FIELD,
        ),
        (
            json.dumps(windows_envelope(source_ip="not-an-ip")),
            NormalizationErrorCode.INVALID_FIELD,
        ),
        (
            json.dumps(
                {
                    "source_type": "unknown.vendor",
                    "record_id": "unknown-1",
                    "payload": {},
                }
            ),
            NormalizationErrorCode.UNSUPPORTED_SOURCE,
        ),
        (
            json.dumps(windows_envelope(event_code=9999)),
            NormalizationErrorCode.UNSUPPORTED_EVENT,
        ),
        (
            json.dumps(linux_envelope(result="maybe")),
            NormalizationErrorCode.UNSUPPORTED_EVENT,
        ),
    ],
)
def test_expected_data_errors_become_rejections(
    raw_text: str,
    expected_code: NormalizationErrorCode,
) -> None:
    record = RawRecord(Path("invalid.jsonl"), 7, raw_text)

    results = list(build_engine().normalize([record], continue_on_error=True))

    assert len(results) == 1
    failure = results[0]
    assert isinstance(failure, NormalizationFailure)
    assert failure.line_number == 7
    assert failure.error_code == expected_code


def test_strict_mode_stops_before_writing_output(tmp_path: Path) -> None:
    input_path = tmp_path / "invalid.jsonl"
    output_path = tmp_path / "normalized.jsonl"
    input_path.write_text("{broken\n", encoding="utf-8")

    with pytest.raises(NormalizationError, match="invalid_json"):
        run_normalization(input_path, output_path)

    assert not output_path.exists()


def test_continue_mode_writes_events_rejections_and_report(tmp_path: Path) -> None:
    input_path = tmp_path / "mixed.jsonl"
    output_path = tmp_path / "normalized.jsonl"
    rejected_path = tmp_path / "rejected.jsonl"
    records = [
        json.dumps(windows_envelope()),
        json.dumps(windows_envelope(record_id="bad-ip", source_ip="invalid")),
    ]
    input_path.write_text("\n".join(records) + "\n", encoding="utf-8")

    report = run_normalization(
        input_path,
        output_path,
        rejected_output_path=rejected_path,
        continue_on_error=True,
    )

    assert report.records_read == 2
    assert report.events_normalized == 1
    assert report.events_rejected == 1
    assert report.by_source == {"windows.security": 2}
    assert report.by_error_code == {"invalid_field": 1}
    assert len(list(read_events(output_path))) == 1

    rejections = [json.loads(line) for line in rejected_path.read_text().splitlines()]
    assert rejections[0]["error_code"] == "invalid_field"
    assert "payload" not in rejections[0]


def test_continue_mode_requires_rejected_output(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires a rejected output"):
        run_normalization(
            Path("input.jsonl"),
            tmp_path / "output.jsonl",
            continue_on_error=True,
        )


@pytest.mark.parametrize(
    "raw_dataset",
    [
        Path("data/raw/windows_brute_force.jsonl"),
        Path("data/raw/linux_brute_force.jsonl"),
    ],
)
def test_raw_brute_force_dataset_generates_one_alert(
    raw_dataset: Path,
    tmp_path: Path,
) -> None:
    normalized_path = tmp_path / f"{raw_dataset.stem}-normalized.jsonl"
    alerts_path = tmp_path / f"{raw_dataset.stem}-alerts.jsonl"

    report = run_normalization(raw_dataset, normalized_path)
    alert_count = run_detection(normalized_path, alerts_path)

    assert report.events_normalized == 5
    assert report.events_rejected == 0
    assert alert_count == 1


@pytest.mark.parametrize(
    ("raw_dataset", "expected_count"),
    [
        (Path("data/raw/windows_activity.jsonl"), 3),
        (Path("data/raw/linux_activity.jsonl"), 4),
    ],
)
def test_activity_datasets_normalize_multiple_log_families(
    raw_dataset: Path, expected_count: int, tmp_path: Path
) -> None:
    normalized_path = tmp_path / f"{raw_dataset.stem}-normalized.jsonl"

    report = run_normalization(raw_dataset, normalized_path)

    assert report.events_normalized == expected_count
    assert report.events_rejected == 0
    assert len(list(read_events(normalized_path))) == expected_count


def test_normalization_output_is_reproducible(tmp_path: Path) -> None:
    input_path = Path("data/raw/windows_brute_force.jsonl")
    first_path = tmp_path / "first.jsonl"
    second_path = tmp_path / "second.jsonl"

    run_normalization(input_path, first_path)
    run_normalization(input_path, second_path)

    assert first_path.read_bytes() == second_path.read_bytes()


def test_duplicate_normalizer_registration_is_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate normalizer"):
        NormalizationEngine(
            [
                WindowsAuthenticationNormalizer(),
                WindowsAuthenticationNormalizer(),
            ]
        )


def test_raw_reader_preserves_source_location(tmp_path: Path) -> None:
    input_path = tmp_path / "raw.jsonl"
    input_path.write_text("\n{}\n\n{}\n", encoding="utf-8")

    records = list(read_raw_records(input_path))

    assert [record.line_number for record in records] == [2, 4]
    assert all(record.input_path == input_path for record in records)
