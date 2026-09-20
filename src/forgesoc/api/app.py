import json
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
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
    AlertWorkflowRequest,
    AuditResponse,
    AuthStatusResponse,
    BootstrapRequest,
    CaseCreateRequest,
    CaseResponse,
    CaseUpdateRequest,
    CoverageResponse,
    DemoSeedRequest,
    DetectionRequest,
    DetectionResponse,
    DetectionRuleResponse,
    ErrorResponse,
    EventImportRequest,
    EventPageResponse,
    EventResponse,
    EventTypeCoverageResponse,
    IngestionResponse,
    LogCoverageResponse,
    LoginRequest,
    NormalizationIngestionResponse,
    NoteCreateRequest,
    NoteResponse,
    RawImportRequest,
    RejectionResponse,
    ScenarioResponse,
    StatsResponse,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
)
from forgesoc.api.security import (
    InvalidTokenError,
    UserIdentity,
    create_token,
    decode_token,
    hash_password,
    verify_password,
)
from forgesoc.detection.engine import DetectionEngine
from forgesoc.detection.registry import default_detectors, detection_catalog
from forgesoc.domain.models import EventType
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
from forgesoc.persistence.repositories import (
    AlertRepository,
    EventRepository,
    UserRepository,
    WorkflowRepository,
)
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


def _identity(request: Request) -> UserIdentity:
    identity = getattr(request.state, "identity", None)
    if not isinstance(identity, UserIdentity):
        raise HTTPException(status_code=401, detail="authentication required")
    return identity


def _require_roles(request: Request, *roles: str) -> UserIdentity:
    identity = _identity(request)
    if identity.role not in roles:
        raise HTTPException(status_code=403, detail="insufficient permissions")
    return identity


def _optional_user_id(
    session_factory: SessionFactory, user_id: str | None
) -> UUID | None:
    if user_id is None:
        return None
    try:
        identifier = UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid user ID") from exc
    with session_factory() as session:
        user = UserRepository(session).get(user_id)
        if user is None or not user.active:
            raise HTTPException(status_code=400, detail="assignee not found")
    return identifier


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

    @app.middleware("http")
    async def authenticate_api(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        public_paths = {
            "/api/v1/auth/status",
            "/api/v1/auth/bootstrap",
            "/api/v1/auth/login",
        }
        if (
            request.url.path.startswith("/api/v1/")
            and request.url.path not in public_paths
        ):
            if not hasattr(request.state, "request_id"):
                request.state.request_id = str(uuid4())
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                response = _error(
                    request, 401, "authentication_required", "authentication required"
                )
                response.headers["X-Request-ID"] = _request_id(request)
                return response
            try:
                token_identity = decode_token(authorization.removeprefix("Bearer "))
                with _session_factory(request)() as session:
                    user = UserRepository(session).get(token_identity.user_id)
                    if user is None or not user.active:
                        raise InvalidTokenError("inactive or unknown user")
                    request.state.identity = UserIdentity(
                        user_id=str(user.user_id),
                        username=user.username,
                        role=user.role,
                    )
            except (InvalidTokenError, ValueError):
                response = _error(request, 401, "invalid_session", "invalid session")
                response.headers["X-Request-ID"] = _request_id(request)
                return response
        return await call_next(request)

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

    @app.get(
        "/api/v1/auth/status",
        response_model=AuthStatusResponse,
        tags=["authentication"],
    )
    def auth_status(request: Request) -> AuthStatusResponse:
        with _session_factory(request)() as session:
            initialized = UserRepository(session).count() > 0
        return AuthStatusResponse(initialized=initialized)

    @app.post(
        "/api/v1/auth/bootstrap",
        response_model=TokenResponse,
        tags=["authentication"],
    )
    def bootstrap(payload: BootstrapRequest, request: Request) -> TokenResponse:
        with _session_factory(request).begin() as session:
            users = UserRepository(session)
            if users.count() > 0:
                raise HTTPException(
                    status_code=409, detail="ForgeSOC is already initialized"
                )
            user = users.create(
                payload.username, hash_password(payload.password), "admin"
            )
            identity = UserIdentity(user.user_id, user.username, user.role)
            WorkflowRepository(session).audit(
                actor_user_id=user.user_id,
                action="system.bootstrap",
                entity_type="user",
                entity_id=user.user_id,
            )
        return TokenResponse(
            access_token=create_token(identity), user=UserResponse.from_record(user)
        )

    @app.post(
        "/api/v1/auth/login",
        response_model=TokenResponse,
        tags=["authentication"],
    )
    def login(payload: LoginRequest, request: Request) -> TokenResponse:
        with _session_factory(request)() as session:
            row = UserRepository(session).by_username(payload.username)
            if (
                row is None
                or not row.active
                or not verify_password(payload.password, row.password_hash)
            ):
                raise HTTPException(status_code=401, detail="invalid credentials")
            user = UserRepository._record(row)
        identity = UserIdentity(user.user_id, user.username, user.role)
        return TokenResponse(
            access_token=create_token(identity), user=UserResponse.from_record(user)
        )

    @app.get("/api/v1/auth/me", response_model=UserResponse, tags=["authentication"])
    def me(request: Request) -> UserResponse:
        identity = _identity(request)
        with _session_factory(request)() as session:
            row = UserRepository(session).get(identity.user_id)
            assert row is not None
            return UserResponse.from_record(UserRepository._record(row))

    @app.get("/api/v1/users", response_model=list[UserResponse], tags=["users"])
    def users(request: Request) -> list[UserResponse]:
        _identity(request)
        with _session_factory(request)() as session:
            return [
                UserResponse.from_record(user)
                for user in UserRepository(session).list()
            ]

    @app.post("/api/v1/users", response_model=UserResponse, tags=["users"])
    def create_user(payload: UserCreateRequest, request: Request) -> UserResponse:
        actor = _require_roles(request, "admin")
        with _session_factory(request).begin() as session:
            users = UserRepository(session)
            if users.by_username(payload.username) is not None:
                raise HTTPException(status_code=409, detail="username already exists")
            user = users.create(
                payload.username, hash_password(payload.password), payload.role.value
            )
            WorkflowRepository(session).audit(
                actor_user_id=actor.user_id,
                action="user.created",
                entity_type="user",
                entity_id=user.user_id,
                details={"role": payload.role.value},
            )
        return UserResponse.from_record(user)

    @app.get("/api/v1/stats", response_model=StatsResponse, tags=["overview"])
    def stats(request: Request) -> StatsResponse:
        result = DatabaseStatsService(_session_factory(request)).get()
        return StatsResponse.from_domain(result)

    @app.get(
        "/api/v1/coverage",
        response_model=CoverageResponse,
        tags=["detections"],
    )
    def coverage(request: Request) -> CoverageResponse:
        metadata = detection_catalog()
        stats_result = DatabaseStatsService(_session_factory(request)).get()
        log_types = sorted(
            set(stats_result.events_by_source)
            | {log_type for rule in metadata for log_type in rule.log_types}
        )
        by_log_type = []
        for log_type in log_types:
            matching = tuple(rule for rule in metadata if log_type in rule.log_types)
            by_log_type.append(
                LogCoverageResponse(
                    log_type=log_type,
                    telemetry_events=stats_result.events_by_source.get(log_type, 0),
                    rule_ids=tuple(rule.rule_id for rule in matching),
                    technique_ids=tuple(
                        sorted(
                            {
                                item.technique_id
                                for rule in matching
                                for item in rule.mitre
                            }
                        )
                    ),
                )
            )
        techniques = {item.technique_id for rule in metadata for item in rule.mitre}
        platforms = {platform for rule in metadata for platform in rule.platforms}
        by_event_type = []
        for event_type in EventType:
            matching = tuple(
                rule for rule in metadata if event_type in rule.event_types
            )
            by_event_type.append(
                EventTypeCoverageResponse(
                    event_type=event_type,
                    telemetry_events=stats_result.events_by_type.get(
                        event_type.value, 0
                    ),
                    rule_ids=tuple(rule.rule_id for rule in matching),
                    technique_ids=tuple(
                        sorted(
                            {
                                item.technique_id
                                for rule in matching
                                for item in rule.mitre
                            }
                        )
                    ),
                )
            )
        return CoverageResponse(
            rule_count=len(metadata),
            technique_count=len(techniques),
            platform_count=len(platforms),
            rules=tuple(DetectionRuleResponse.from_metadata(rule) for rule in metadata),
            by_log_type=tuple(by_log_type),
            by_event_type=tuple(by_event_type),
        )

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
        _require_roles(request, "admin", "analyst")
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
        _require_roles(request, "admin", "analyst")
        records = [
            RawRecord(
                input_path=Path("<web-import>"),
                line_number=index,
                raw_text=json.dumps(record),
            )
            for index, record in enumerate(payload.records, start=1)
        ]
        results = list(build_engine().normalize(records, continue_on_error=True))
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
        status: str | None = None,
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
            status=status,
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

    @app.patch(
        "/api/v1/alerts/{alert_id}/workflow",
        response_model=AlertResponse,
        tags=["workflow"],
    )
    def update_alert_workflow(
        alert_id: UUID,
        payload: AlertWorkflowRequest,
        request: Request,
    ) -> AlertResponse:
        actor = _require_roles(request, "admin", "analyst")
        if payload.status.value != "closed" and payload.disposition is not None:
            raise HTTPException(
                status_code=400, detail="disposition is only valid for closed alerts"
            )
        assignee_id = _optional_user_id(
            _session_factory(request), payload.assignee_user_id
        )
        with _session_factory(request).begin() as session:
            alerts_repository = AlertRepository(session)
            updated = alerts_repository.update_workflow(
                str(alert_id),
                status=payload.status.value,
                assignee_user_id=assignee_id,
                disposition=(
                    payload.disposition.value if payload.disposition else None
                ),
            )
            if not updated:
                raise HTTPException(status_code=404, detail="alert not found")
            WorkflowRepository(session).audit(
                actor_user_id=actor.user_id,
                action="alert.workflow_updated",
                entity_type="alert",
                entity_id=str(alert_id),
                details={
                    "status": payload.status.value,
                    "assignee_user_id": payload.assignee_user_id,
                    "disposition": (
                        payload.disposition.value if payload.disposition else None
                    ),
                },
            )
            session.flush()
            alert = alerts_repository.get(str(alert_id))
            assert alert is not None
        return AlertResponse.from_domain(alert)

    @app.get(
        "/api/v1/alerts/{alert_id}/notes",
        response_model=list[NoteResponse],
        tags=["workflow"],
    )
    def alert_notes(alert_id: UUID, request: Request) -> list[NoteResponse]:
        with _session_factory(request)() as session:
            if AlertRepository(session).get(str(alert_id)) is None:
                raise HTTPException(status_code=404, detail="alert not found")
            return [
                NoteResponse.from_record(note)
                for note in WorkflowRepository(session).notes(str(alert_id))
            ]

    @app.post(
        "/api/v1/alerts/{alert_id}/notes",
        response_model=NoteResponse,
        tags=["workflow"],
    )
    def add_alert_note(
        alert_id: UUID, payload: NoteCreateRequest, request: Request
    ) -> NoteResponse:
        actor = _require_roles(request, "admin", "analyst")
        with _session_factory(request).begin() as session:
            if AlertRepository(session).get(str(alert_id)) is None:
                raise HTTPException(status_code=404, detail="alert not found")
            workflow = WorkflowRepository(session)
            note = workflow.add_note(str(alert_id), actor.user_id, payload.body)
            workflow.audit(
                actor_user_id=actor.user_id,
                action="alert.note_added",
                entity_type="alert",
                entity_id=str(alert_id),
            )
        return NoteResponse.from_record(note)

    @app.get("/api/v1/cases", response_model=list[CaseResponse], tags=["workflow"])
    def cases(request: Request) -> list[CaseResponse]:
        with _session_factory(request)() as session:
            return [
                CaseResponse.from_record(case)
                for case in WorkflowRepository(session).list_cases()
            ]

    @app.post("/api/v1/cases", response_model=CaseResponse, tags=["workflow"])
    def create_case(payload: CaseCreateRequest, request: Request) -> CaseResponse:
        actor = _require_roles(request, "admin", "analyst")
        assignee_id = _optional_user_id(
            _session_factory(request), payload.assignee_user_id
        )
        with _session_factory(request).begin() as session:
            alerts_repository = AlertRepository(session)
            missing = [
                alert_id
                for alert_id in payload.alert_ids
                if alerts_repository.get(alert_id) is None
            ]
            if missing:
                raise HTTPException(
                    status_code=400, detail="case contains unknown alerts"
                )
            workflow = WorkflowRepository(session)
            case = workflow.create_case(
                title=payload.title,
                description=payload.description,
                priority=payload.priority.value,
                assignee_user_id=assignee_id,
                created_by_user_id=UUID(actor.user_id),
                alert_ids=payload.alert_ids,
            )
            workflow.audit(
                actor_user_id=actor.user_id,
                action="case.created",
                entity_type="case",
                entity_id=case.case_id,
                details={"alert_count": len(payload.alert_ids)},
            )
        return CaseResponse.from_record(case)

    @app.patch(
        "/api/v1/cases/{case_id}",
        response_model=CaseResponse,
        tags=["workflow"],
    )
    def update_case(
        case_id: UUID, payload: CaseUpdateRequest, request: Request
    ) -> CaseResponse:
        actor = _require_roles(request, "admin", "analyst")
        assignee_id = _optional_user_id(
            _session_factory(request), payload.assignee_user_id
        )
        with _session_factory(request).begin() as session:
            workflow = WorkflowRepository(session)
            case = workflow.update_case(
                str(case_id), status=payload.status.value, assignee_user_id=assignee_id
            )
            if case is None:
                raise HTTPException(status_code=404, detail="case not found")
            workflow.audit(
                actor_user_id=actor.user_id,
                action="case.updated",
                entity_type="case",
                entity_id=str(case_id),
                details={"status": payload.status.value},
            )
        return CaseResponse.from_record(case)

    @app.get(
        "/api/v1/audit",
        response_model=list[AuditResponse],
        tags=["workflow"],
    )
    def audit_log(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[AuditResponse]:
        _require_roles(request, "admin")
        with _session_factory(request)() as session:
            return [
                AuditResponse.from_record(item)
                for item in WorkflowRepository(session).audit_log(limit)
            ]

    @app.get(
        "/api/v1/scenarios",
        response_model=list[ScenarioResponse],
        tags=["operations"],
    )
    def scenarios() -> list[ScenarioResponse]:
        responses = []
        for name, scenario in sorted(SCENARIOS.items()):
            events = tuple(
                scenario.generate(
                    TelemetryGenerator(name, 42, datetime(2026, 1, 1, tzinfo=UTC))
                )
            )
            alerts = tuple(DetectionEngine(default_detectors()).process(events))
            responses.append(
                ScenarioResponse(
                    name=name,
                    description=scenario.description,
                    event_count=len(events),
                    event_types=tuple(sorted({event.event_type for event in events})),
                    expected_rule_ids=tuple(
                        sorted({alert.rule_id for alert in alerts})
                    ),
                )
            )
        return responses

    @app.post(
        "/api/v1/demo/seed",
        response_model=IngestionResponse,
        tags=["operations"],
    )
    def seed_demo(payload: DemoSeedRequest, request: Request) -> IngestionResponse:
        _require_roles(request, "admin", "analyst")
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
        _require_roles(request, "admin", "analyst")
        try:
            summary = DatabaseDetectionService(
                _session_factory(request),
                detector_factory=default_detectors,
            ).detect(payload.start, payload.end)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return DetectionResponse.from_domain(summary)

    return app
