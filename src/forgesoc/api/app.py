import json
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, cast
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from forgesoc.api.pagination import (
    InvalidCursorError,
    decode_cursor,
    encode_cursor,
)
from forgesoc.api.schemas import (
    AlertPageResponse,
    AlertResponse,
    DemoSeedRequest,
    DetectionRequest,
    DetectionResponse,
    ErrorResponse,
    EventImportRequest,
    EventPageResponse,
    EventResponse,
    IngestionResponse,
    NormalizationIngestionResponse,
    RawImportRequest,
    RejectionResponse,
    ScenarioResponse,
    StatsResponse,
)
from forgesoc.detection.brute_force import BruteForceDetector
from forgesoc.ingestion.raw_jsonl import RawRecord
from forgesoc.normalization.main import build_engine
from forgesoc.normalization.models import NormalizationFailure, NormalizationSuccess
from forgesoc.persistence.config import DatabaseConfig
from forgesoc.persistence.database import (
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from forgesoc.persistence.models import AlertQuery, EventQuery
from forgesoc.persistence.repositories import AlertRepository, EventRepository
from forgesoc.persistence.services import (
    DatabaseDetectionService,
    DatabaseStatsService,
    EventIngestionService,
)
from forgesoc.simulation.generator import TelemetryGenerator
from forgesoc.simulation.scenarios import SCENARIOS, get_scenario

STATIC_DIRECTORY = Path(__file__).with_name("static")


def _session_factory(request: Request) -> SessionFactory:
    return cast(SessionFactory, request.app.state.session_factory)


def _request_id(request: Request) -> str:
    return cast(str, getattr(request.state, "request_id", "unknown"))


def _error(request: Request, status_code: int, code: str, message: str) -> JSONResponse:
    body = ErrorResponse(
        code=code,
        message=message,
        request_id=_request_id(request),
    )
    return JSONResponse(status_code=status_code, content=body.model_dump())


def _validate_range(start: datetime | None, end: datetime | None) -> None:
    if start is not None and start.tzinfo is None:
        raise HTTPException(status_code=400, detail="start must include a timezone")
    if end is not None and end.tzinfo is None:
        raise HTTPException(status_code=400, detail="end must include a timezone")
    if start is not None and end is not None and start >= end:
        raise HTTPException(status_code=400, detail="start must be earlier than end")


def _validate_ip(value: str | None) -> None:
    if value is None:
        return
    try:
        ip_address(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid source IP") from exc


def create_app(session_factory: SessionFactory | None = None) -> FastAPI:
    owned_engine = None
    if session_factory is None:
        owned_engine = create_database_engine(DatabaseConfig.from_environment())
        session_factory = create_session_factory(owned_engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        if owned_engine is not None:
            owned_engine.dispose()

    app = FastAPI(
        title="ForgeSOC API",
        summary="Detection telemetry, alerts, evidence, and workshop operations.",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.session_factory = session_factory
    app.mount("/static", StaticFiles(directory=STATIC_DIRECTORY), name="static")

    @app.middleware("http")
    async def request_context(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        supplied_request_id = request.headers.get("X-Request-ID", "")
        request_id = (
            supplied_request_id
            if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", supplied_request_id)
            else str(uuid4())
        )
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = (
            f"{(time.perf_counter() - started) * 1000:.2f}"
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        first_error = exc.errors()[0] if exc.errors() else {}
        message = str(first_error.get("msg", "request validation failed"))
        return _error(request, 422, "invalid_request", message)

    @app.exception_handler(InvalidCursorError)
    async def cursor_error(request: Request, exc: InvalidCursorError) -> JSONResponse:
        return _error(request, 400, "invalid_cursor", str(exc))

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        del exc
        return _error(request, 503, "database_unavailable", "database unavailable")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        return _error(request, exc.status_code, "http_error", str(exc.detail))

    @app.get("/", include_in_schema=False, response_class=FileResponse)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIRECTORY / "index.html")

    @app.get("/health/live", tags=["health"])
    def live() -> dict[str, str]:
        return {"status": "ok", "service": "forgesoc-api"}

    @app.get("/health/ready", tags=["health"])
    def ready(request: Request) -> dict[str, str]:
        with _session_factory(request)() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}

    @app.get("/api/v1/stats", response_model=StatsResponse, tags=["overview"])
    def stats(request: Request) -> StatsResponse:
        result = DatabaseStatsService(_session_factory(request)).get()
        return StatsResponse.from_domain(result)

    @app.get(
        "/api/v1/events",
        response_model=EventPageResponse,
        tags=["events"],
    )
    def events(
        request: Request,
        start: datetime | None = None,
        end: datetime | None = None,
        event_type: str | None = None,
        source: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        outcome: str | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        cursor: str | None = None,
    ) -> EventPageResponse:
        _validate_range(start, end)
        _validate_ip(source_ip)
        cursor_timestamp, cursor_id = decode_cursor(cursor)
        query = EventQuery(
            start=start,
            end=end,
            event_type=event_type,
            source=source,
            username=username,
            source_ip=source_ip,
            outcome=outcome,
            cursor_timestamp=cursor_timestamp,
            cursor_id=cursor_id,
            limit=limit,
        )
        with _session_factory(request)() as session:
            page = EventRepository(session).search(query)
        next_cursor = None
        if page.has_more and page.items:
            last = page.items[-1]
            next_cursor = encode_cursor(last.timestamp, last.event_id)
        return EventPageResponse(
            items=[EventResponse.from_domain(item) for item in page.items],
            next_cursor=next_cursor,
        )

    @app.get(
        "/api/v1/events/{event_id}",
        response_model=EventResponse,
        tags=["events"],
    )
    def event_detail(event_id: str, request: Request) -> EventResponse:
        with _session_factory(request)() as session:
            event = EventRepository(session).get(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        return EventResponse.from_domain(event)

    @app.post(
        "/api/v1/events/import",
        response_model=IngestionResponse,
        tags=["operations"],
    )
    def import_events(
        payload: EventImportRequest,
        request: Request,
    ) -> IngestionResponse:
        summary = EventIngestionService(_session_factory(request)).ingest(
            event.to_domain() for event in payload.events
        )
        return IngestionResponse.from_domain(summary)

    @app.post(
        "/api/v1/raw/import",
        response_model=NormalizationIngestionResponse,
        tags=["operations"],
    )
    def import_raw_records(
        payload: RawImportRequest,
        request: Request,
    ) -> NormalizationIngestionResponse:
        records = [
            RawRecord(
                input_path=Path("<web-import>"),
                line_number=index,
                raw_text=json.dumps(record),
            )
            for index, record in enumerate(payload.records, start=1)
        ]
        results = list(
            build_engine().normalize(records, continue_on_error=True)
        )
        successes = [
            result for result in results if isinstance(result, NormalizationSuccess)
        ]
        failures = [
            result for result in results if isinstance(result, NormalizationFailure)
        ]
        summary = EventIngestionService(_session_factory(request)).ingest(
            result.event for result in successes
        )
        return NormalizationIngestionResponse(
            records_received=len(results),
            events_normalized=len(successes),
            events_rejected=len(failures),
            events_inserted=summary.events_inserted,
            duplicates=summary.duplicates,
            rejections=[
                RejectionResponse(
                    line_number=failure.line_number,
                    source_type=failure.source_type,
                    source_record_id=failure.source_record_id,
                    error_code=failure.error_code.value,
                    message=failure.message,
                )
                for failure in failures
            ],
        )

    @app.get(
        "/api/v1/alerts",
        response_model=AlertPageResponse,
        tags=["alerts"],
    )
    def alerts(
        request: Request,
        start: datetime | None = None,
        end: datetime | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        cursor: str | None = None,
    ) -> AlertPageResponse:
        _validate_range(start, end)
        _validate_ip(source_ip)
        cursor_timestamp, cursor_id = decode_cursor(cursor)
        if cursor_id is not None:
            try:
                UUID(cursor_id)
            except ValueError as exc:
                raise InvalidCursorError("invalid pagination cursor") from exc
        query = AlertQuery(
            start=start,
            end=end,
            severity=severity,
            rule_id=rule_id,
            username=username,
            source_ip=source_ip,
            cursor_timestamp=cursor_timestamp,
            cursor_id=cursor_id,
            limit=limit,
        )
        with _session_factory(request)() as session:
            page = AlertRepository(session).search(query)
        next_cursor = None
        if page.has_more and page.items:
            last = page.items[-1]
            next_cursor = encode_cursor(last.timestamp, last.alert_id)
        return AlertPageResponse(
            items=[AlertResponse.from_domain(item) for item in page.items],
            next_cursor=next_cursor,
        )

    @app.get(
        "/api/v1/alerts/{alert_id}",
        response_model=AlertResponse,
        tags=["alerts"],
    )
    def alert_detail(alert_id: UUID, request: Request) -> AlertResponse:
        with _session_factory(request)() as session:
            alert = AlertRepository(session).get(str(alert_id))
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return AlertResponse.from_domain(alert)

    @app.get(
        "/api/v1/alerts/{alert_id}/events",
        response_model=list[EventResponse],
        tags=["alerts"],
    )
    def alert_evidence(alert_id: UUID, request: Request) -> list[EventResponse]:
        with _session_factory(request)() as session:
            evidence = AlertRepository(session).evidence(str(alert_id))
        if evidence is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return [EventResponse.from_domain(event) for event in evidence]

    @app.get(
        "/api/v1/scenarios",
        response_model=list[ScenarioResponse],
        tags=["operations"],
    )
    def scenarios() -> list[ScenarioResponse]:
        return [
            ScenarioResponse(name=name, description=scenario.description)
            for name, scenario in sorted(SCENARIOS.items())
        ]

    @app.post(
        "/api/v1/demo/seed",
        response_model=IngestionResponse,
        tags=["operations"],
    )
    def seed_demo(payload: DemoSeedRequest, request: Request) -> IngestionResponse:
        try:
            scenario = get_scenario(payload.scenario)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        generator = TelemetryGenerator(
            scenario.name,
            payload.seed,
            payload.start_time,
        )
        summary = EventIngestionService(_session_factory(request)).ingest(
            scenario.generate(generator)
        )
        return IngestionResponse.from_domain(summary)

    @app.post(
        "/api/v1/detections/run",
        response_model=DetectionResponse,
        tags=["operations"],
    )
    def run_detection(
        payload: DetectionRequest,
        request: Request,
    ) -> DetectionResponse:
        try:
            summary = DatabaseDetectionService(
                _session_factory(request),
                detector_factory=lambda: [BruteForceDetector()],
            ).detect(payload.start, payload.end)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return DetectionResponse.from_domain(summary)

    return app
