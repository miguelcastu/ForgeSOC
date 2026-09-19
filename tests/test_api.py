from sqlalchemy.orm import Session, sessionmaker
from starlette.testclient import TestClient

from forgesoc.api.app import create_app


def test_dashboard_and_openapi_are_served_without_database_access() -> None:
    app = create_app(sessionmaker(class_=Session))

    with TestClient(app) as client:
        dashboard = client.get("/")
        openapi = client.get("/api/openapi.json")

    assert dashboard.status_code == 200
    assert "ForgeSOC" in dashboard.text
    assert openapi.status_code == 200
    assert openapi.json()["info"]["title"] == "ForgeSOC API"


def test_liveness_adds_request_observability_headers() -> None:
    app = create_app(sessionmaker(class_=Session))

    with TestClient(app) as client:
        response = client.get("/health/live", headers={"X-Request-ID": "test-123"})

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-123"
    assert float(response.headers["X-Response-Time-Ms"]) >= 0


def test_invalid_cursor_uses_stable_error_contract() -> None:
    app = create_app(sessionmaker(class_=Session))

    with TestClient(app) as client:
        response = client.get("/api/v1/events?cursor=broken")

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_cursor"
    assert response.json()["request_id"]
