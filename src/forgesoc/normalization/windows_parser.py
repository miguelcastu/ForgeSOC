from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from forgesoc.domain.models import (
    AuthenticationOutcome,
    EventType,
    JsonValue,
    SecurityEvent,
)
from forgesoc.normalization.base import UnsupportedEventError, stable_event_id
from forgesoc.normalization.schemas import RawEventEnvelope


class WindowsAuthenticationPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_code: int = Field(alias="EventID")
    time_created: datetime = Field(alias="TimeCreated")
    computer: str = Field(alias="Computer", min_length=1)
    username: str = Field(alias="TargetUserName", min_length=1)
    source_ip: IPvAnyAddress = Field(alias="IpAddress")
    logon_type: Annotated[int, Field(ge=0)] = Field(alias="LogonType")
    authentication_package: str = Field(
        alias="AuthenticationPackageName",
        min_length=1,
    )
    status: str | None = Field(default=None, alias="Status")
    sub_status: str | None = Field(default=None, alias="SubStatus")

    @field_validator("time_created")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("TimeCreated must include a timezone")
        return value


class WindowsProcessPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_code: int = Field(alias="EventID")
    time_created: datetime = Field(alias="TimeCreated")
    computer: str = Field(alias="Computer", min_length=1)
    username: str | None = Field(default=None, alias="SubjectUserName")
    process_name: str = Field(alias="NewProcessName", min_length=1)
    command_line: str = Field(alias="CommandLine", min_length=1)
    parent_process: str | None = Field(default=None, alias="ParentProcessName")

    @field_validator("time_created")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("TimeCreated must include a timezone")
        return value


class WindowsServicePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_code: int = Field(alias="EventID")
    time_created: datetime = Field(alias="TimeCreated")
    computer: str = Field(alias="Computer", min_length=1)
    username: str | None = Field(default=None, alias="SubjectUserName")
    service_name: str = Field(alias="ServiceName", min_length=1)
    service_path: str = Field(alias="ServiceFileName", min_length=1)
    service_start_type: str | None = Field(default=None, alias="ServiceStartType")

    @field_validator("time_created")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("TimeCreated must include a timezone")
        return value


class WindowsSysmonPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_code: int = Field(alias="EventID")
    time_created: datetime = Field(alias="UtcTime")
    computer: str = Field(alias="Computer", min_length=1)
    username: str | None = Field(default=None, alias="User")
    image: str | None = Field(default=None, alias="Image")
    command_line: str | None = Field(default=None, alias="CommandLine")
    parent_image: str | None = Field(default=None, alias="ParentImage")
    source_ip: IPvAnyAddress | None = Field(default=None, alias="SourceIp")
    destination_ip: IPvAnyAddress | None = Field(default=None, alias="DestinationIp")
    destination_port: int | None = Field(default=None, alias="DestinationPort")
    query_name: str | None = Field(default=None, alias="QueryName")

    @field_validator("time_created")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("UtcTime must include a timezone")
        return value


class WindowsAuthenticationNormalizer:
    source_type = "windows.security"

    def normalize(self, envelope: RawEventEnvelope) -> SecurityEvent:
        event_code = envelope.payload.get("EventID")
        if event_code == 4688:
            return self._process_event(envelope)
        if event_code == 4697:
            return self._service_event(envelope)
        payload = WindowsAuthenticationPayload.model_validate(envelope.payload)

        if payload.event_code == 4624:
            event_type = EventType.AUTHENTICATION_SUCCESS
            outcome = AuthenticationOutcome.SUCCESS
        elif payload.event_code == 4625:
            event_type = EventType.AUTHENTICATION_FAILURE
            outcome = AuthenticationOutcome.FAILURE
        else:
            raise UnsupportedEventError(
                f"Windows EventID {payload.event_code} is not supported"
            )

        attributes: dict[str, JsonValue] = {
            "event_code": payload.event_code,
            "logon_type": payload.logon_type,
            "authentication_package": payload.authentication_package,
        }
        if payload.status is not None:
            attributes["status"] = payload.status
        if payload.sub_status is not None:
            attributes["sub_status"] = payload.sub_status

        return SecurityEvent(
            event_id=stable_event_id(self.source_type, envelope.record_id),
            timestamp=payload.time_created.astimezone(UTC),
            event_type=event_type,
            source=self.source_type,
            username=payload.username,
            source_ip=str(payload.source_ip),
            outcome=outcome,
            host=payload.computer,
            attributes=attributes,
            source_record_id=envelope.record_id,
        )

    def _process_event(self, envelope: RawEventEnvelope) -> SecurityEvent:
        payload = WindowsProcessPayload.model_validate(envelope.payload)
        return SecurityEvent(
            event_id=stable_event_id(self.source_type, envelope.record_id),
            timestamp=payload.time_created.astimezone(UTC),
            event_type=EventType.PROCESS_START,
            source=self.source_type,
            username=payload.username,
            source_ip=None,
            outcome=None,
            host=payload.computer,
            attributes={
                "event_code": payload.event_code,
                "process_name": payload.process_name,
                "command_line": payload.command_line,
                "parent_process": payload.parent_process,
            },
            source_record_id=envelope.record_id,
        )

    def _service_event(self, envelope: RawEventEnvelope) -> SecurityEvent:
        payload = WindowsServicePayload.model_validate(envelope.payload)
        return SecurityEvent(
            event_id=stable_event_id(self.source_type, envelope.record_id),
            timestamp=payload.time_created.astimezone(UTC),
            event_type=EventType.SERVICE_INSTALL,
            source=self.source_type,
            username=payload.username,
            source_ip=None,
            outcome=None,
            host=payload.computer,
            attributes={
                "event_code": payload.event_code,
                "service_name": payload.service_name,
                "service_path": payload.service_path,
                "service_start_type": payload.service_start_type,
            },
            source_record_id=envelope.record_id,
        )


class WindowsSysmonNormalizer:
    source_type = "windows.sysmon"

    def normalize(self, envelope: RawEventEnvelope) -> SecurityEvent:
        payload = WindowsSysmonPayload.model_validate(envelope.payload)
        if payload.event_code == 1 and payload.image and payload.command_line:
            event_type = EventType.PROCESS_START
            attributes: dict[str, JsonValue] = {
                "event_code": 1,
                "process_name": payload.image,
                "command_line": payload.command_line,
                "parent_process": payload.parent_image,
            }
        elif (
            payload.event_code == 3
            and payload.destination_ip is not None
            and payload.destination_port is not None
        ):
            event_type = EventType.NETWORK_CONNECTION
            attributes = {
                "event_code": 3,
                "process_name": payload.image,
                "destination_ip": str(payload.destination_ip),
                "destination_port": payload.destination_port,
                "direction": "outbound",
            }
        elif payload.event_code == 22 and payload.query_name:
            event_type = EventType.DNS_QUERY
            attributes = {
                "event_code": 22,
                "process_name": payload.image,
                "query": payload.query_name,
            }
        else:
            raise UnsupportedEventError(
                f"Sysmon EventID {payload.event_code} or its fields are not supported"
            )
        return SecurityEvent(
            event_id=stable_event_id(self.source_type, envelope.record_id),
            timestamp=payload.time_created.astimezone(UTC),
            event_type=event_type,
            source=self.source_type,
            username=payload.username,
            source_ip=str(payload.source_ip) if payload.source_ip else None,
            outcome=None,
            host=payload.computer,
            attributes=attributes,
            source_record_id=envelope.record_id,
        )
