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


class WindowsAuthenticationNormalizer:
    source_type = "windows.security"

    def normalize(self, envelope: RawEventEnvelope) -> SecurityEvent:
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
