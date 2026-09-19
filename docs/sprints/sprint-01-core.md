# Sprint 1: core detection pipeline

## Goal

Build the smallest correct path from synthetic authentication events to a
security alert while introducing clean boundaries and automated verification.

## Detection specification

```text
Rule ID:   AUTH-BRUTEFORCE-001
Condition: >= 5 failed authentications
Group by:  username + source_ip
Window:    60 seconds
Severity:  high
```

A successful authentication resets the pair. Continuous failures after the
threshold produce only one alert until that suppression state is reset.

## Completed tasks

- Created immutable `SecurityEvent` and `Alert` domain models.
- Added streaming JSONL ingestion.
- Defined the `Detector` protocol.
- Added an engine that can orchestrate multiple detectors.
- Implemented stateful brute-force detection.
- Added JSONL alert output and a console entry point.
- Added six detector acceptance tests and one end-to-end pipeline test.
- Added Ruff and pytest to the uv development dependency group.

## Acceptance evidence

| Scenario | Expected | Covered by |
| --- | --- | --- |
| Five failures, same user/IP | One alert | `test_generates_alert_after_five_failures` |
| Four failures | No alert | `test_four_failures_do_not_generate_alert` |
| Five different users | No alert | `test_different_users_are_not_mixed` |
| Four failures, success, four failures | No alert | `test_successful_login_resets_failures` |
| Five failures outside 60 seconds | No alert | `test_failures_outside_time_window_do_not_trigger` |
| Eight continuous failures | One alert | `test_detector_does_not_spam_duplicate_alerts` |
| Sample JSONL pipeline | One valid alert | `test_pipeline_writes_brute_force_alert` |

## Verification

```powershell
uv sync
uv run ruff check .
uv run pytest -v
uv run forgesoc data/security_events.jsonl data/alerts.jsonl
Get-Content data/alerts.jsonl
```

Verified baseline on 2026-09-19:

- Python 3.12.14 from the project `.venv`;
- Ruff: all checks passed;
- pytest: 7 passed;
- CLI: one high-severity `AUTH-BRUTEFORCE-001` alert with five related events.

## Lessons from the repair

Python imports depend on valid module paths. The detector originally lived in a
file without a `.py` extension while application code imported
`forgesoc.detection.brute_force`, so test collection failed before any detector
logic ran. The output adapter was also referenced but absent. Repairing module
boundaries and adding an end-to-end test exposed and prevented both integration
errors.

## Known limitations

The architectural limitations are recorded in the
[architecture overview](../architecture/overview.md). Sprint 2 is deliberately
not implemented here.
