import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from starlette.testclient import TestClient

from forgesoc.api.app import create_app
from forgesoc.persistence.database import SessionFactory

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def api_engine() -> Iterator[Engine]:
    database_url = os.getenv("FORGESOC_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("FORGESOC_TEST_DATABASE_URL is not configured")
    if "test" not in (make_url(database_url).database or "").lower():
        pytest.fail("refusing to run destructive tests outside a test database")
    engine = create_engine(database_url, pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture
def api_client(api_engine: Engine) -> Iterator[TestClient]:
    factory: SessionFactory = sessionmaker(
        bind=api_engine,
        class_=Session,
        expire_on_commit=False,
    )
    with api_engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE audit_log, case_alerts, cases, alert_notes, "
                "alert_events, alerts, events, users RESTART IDENTITY CASCADE"
            )
        )
    with TestClient(create_app(factory)) as client:
        bootstrap = client.post(
            "/api/v1/auth/bootstrap",
            json={"username": "admin", "password": "correct-horse-battery"},
        )
        assert bootstrap.status_code == 200
        client.headers["Authorization"] = f"Bearer {bootstrap.json()['access_token']}"
        yield client


def seed_brute_force(client: TestClient) -> dict[str, int]:
    response = client.post(
        "/api/v1/demo/seed",
        json={
            "scenario": "brute-force",
            "seed": 42,
            "start_time": "2026-09-20T10:00:00Z",
        },
    )
    assert response.status_code == 200
    return response.json()


def test_health_stats_and_scenarios(api_client: TestClient) -> None:
    assert api_client.get("/health/ready").json()["status"] == "ready"
    stats = api_client.get("/api/v1/stats").json()
    scenarios = api_client.get("/api/v1/scenarios").json()

    assert stats["events"] == 0
    assert stats["alerts"] == 0
    assert {item["name"] for item in scenarios} >= {
        "normal-activity",
        "brute-force",
        "credential-spraying",
    }


def test_demo_detection_and_evidence_workflow_is_idempotent(
    api_client: TestClient,
) -> None:
    first_seed = seed_brute_force(api_client)
    second_seed = seed_brute_force(api_client)

    detection_payload = {
        "start": "2026-09-20T00:00:00Z",
        "end": "2026-09-21T00:00:00Z",
    }
    first_detection = api_client.post(
        "/api/v1/detections/run",
        json=detection_payload,
    ).json()
    second_detection = api_client.post(
        "/api/v1/detections/run",
        json=detection_payload,
    ).json()

    alerts = api_client.get("/api/v1/alerts").json()["items"]
    alert_id = alerts[0]["alert_id"]
    evidence = api_client.get(f"/api/v1/alerts/{alert_id}/events").json()

    assert first_seed["events_inserted"] == 6
    assert second_seed["duplicates"] == 6
    assert first_detection["alerts_inserted"] == 1
    assert second_detection["duplicates"] == 1
    assert len(alerts) == 1
    assert len(evidence) == 5
    assert [item["attributes"]["attempt"] for item in evidence] == [1, 2, 3, 4, 5]


def test_event_filters_detail_and_cursor_pagination(api_client: TestClient) -> None:
    seed_brute_force(api_client)

    first_page = api_client.get(
        "/api/v1/events",
        params={"event_type": "authentication.failure", "limit": 2},
    ).json()
    second_page = api_client.get(
        "/api/v1/events",
        params={
            "event_type": "authentication.failure",
            "limit": 2,
            "cursor": first_page["next_cursor"],
        },
    ).json()
    identifiers = {
        item["event_id"] for item in first_page["items"] + second_page["items"]
    }
    detail = api_client.get(f"/api/v1/events/{first_page['items'][0]['event_id']}")

    assert first_page["next_cursor"] is not None
    assert len(identifiers) == 4
    assert detail.status_code == 200
    assert detail.json()["source"] == "windows.eventlog"


def test_canonical_event_import_and_validation(api_client: TestClient) -> None:
    event = {
        "event_id": "api-import-001",
        "timestamp": "2026-09-20T10:00:00Z",
        "event_type": "authentication.success",
        "source": "workshop.import",
        "username": "marta.soler",
        "source_ip": "192.0.2.44",
        "outcome": "success",
        "attributes": {"method": "password"},
    }
    first = api_client.post("/api/v1/events/import", json={"events": [event]})
    second = api_client.post("/api/v1/events/import", json={"events": [event]})
    invalid = api_client.post(
        "/api/v1/events/import",
        json={"events": [{**event, "timestamp": "2026-09-20T10:00:00"}]},
    )

    assert first.json()["events_inserted"] == 1
    assert second.json()["duplicates"] == 1
    assert invalid.status_code == 422
    assert invalid.json()["code"] == "invalid_request"


def test_raw_windows_import_normalizes_and_reports_rejections(
    api_client: TestClient,
) -> None:
    records = [
        json.loads(line)
        for line in Path("data/raw/windows_brute_force.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    records.append(
        {
            "source_type": "unknown.vendor",
            "record_id": "unsupported-1",
            "payload": {},
        }
    )

    response = api_client.post("/api/v1/raw/import", json={"records": records})

    assert response.status_code == 200
    assert response.json()["events_normalized"] == 5
    assert response.json()["events_inserted"] == 5
    assert response.json()["events_rejected"] == 1
    assert response.json()["rejections"][0]["error_code"] == "unsupported_source"


def test_missing_resources_return_consistent_404(api_client: TestClient) -> None:
    event = api_client.get("/api/v1/events/not-found")
    alert = api_client.get("/api/v1/alerts/00000000-0000-0000-0000-000000000000")

    assert event.status_code == 404
    assert event.json()["code"] == "http_error"
    assert alert.status_code == 404


def test_authentication_roles_and_analyst_workflow(api_client: TestClient) -> None:
    analyst = api_client.post(
        "/api/v1/users",
        json={
            "username": "marta.analyst",
            "password": "analyst-password-123",
            "role": "analyst",
        },
    )
    assert analyst.status_code == 200

    seed_brute_force(api_client)
    api_client.post(
        "/api/v1/detections/run",
        json={
            "start": "2026-09-20T00:00:00Z",
            "end": "2026-09-21T00:00:00Z",
        },
    )
    alert_id = api_client.get("/api/v1/alerts").json()["items"][0]["alert_id"]
    workflow = api_client.patch(
        f"/api/v1/alerts/{alert_id}/workflow",
        json={
            "status": "investigating",
            "assignee_user_id": analyst.json()["user_id"],
        },
    )
    note = api_client.post(
        f"/api/v1/alerts/{alert_id}/notes",
        json={"body": "Validated source IP against the evidence."},
    )
    case = api_client.post(
        "/api/v1/cases",
        json={
            "title": "Authentication attack investigation",
            "description": "Correlate the brute-force evidence.",
            "priority": "high",
            "assignee_user_id": analyst.json()["user_id"],
            "alert_ids": [alert_id],
        },
    )
    audit = api_client.get("/api/v1/audit").json()

    assert workflow.status_code == 200
    assert workflow.json()["status"] == "investigating"
    assert workflow.json()["assignee"] == "marta.analyst"
    assert note.json()["author"] == "admin"
    assert case.json()["alert_ids"] == [alert_id]
    assert {item["action"] for item in audit} >= {
        "user.created",
        "alert.workflow_updated",
        "alert.note_added",
        "case.created",
    }


def test_viewer_cannot_mutate_security_data(api_client: TestClient) -> None:
    api_client.post(
        "/api/v1/users",
        json={
            "username": "readonly",
            "password": "viewer-password-1234",
            "role": "viewer",
        },
    )
    login = api_client.post(
        "/api/v1/auth/login",
        json={"username": "readonly", "password": "viewer-password-1234"},
    )
    viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    response = api_client.post(
        "/api/v1/demo/seed",
        headers=viewer_headers,
        json={
            "scenario": "brute-force",
            "seed": 42,
            "start_time": "2026-09-20T10:00:00Z",
        },
    )

    assert response.status_code == 403
    assert response.json()["message"] == "insufficient permissions"
