from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from forgesoc.domain.models import (
    AuthenticationOutcome,
    EventType,
    JsonValue,
    SecurityEvent,
)
from forgesoc.normalization.base import UnsupportedEventError, stable_event_id
from forgesoc.normalization.schemas import RawEventEnvelope


class LinuxSshPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: datetime
    hostname: str = Field(min_length=1)
    program: str = Field(min_length=1)
    user: str = Field(min_length=1)
    remote_addr: IPvAnyAddress
    remote_port: Annotated[int, Field(ge=1, le=65535)]
    result: str = Field(min_length=1)
    authentication_method: Literal["password", "publickey"]
    message: str = Field(min_length=1)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value


class LinuxSshNormalizer:
    source_type = "linux.ssh"

    def normalize(self, envelope: RawEventEnvelope) -> SecurityEvent:
        payload = LinuxSshPayload.model_validate(envelope.payload)

        if payload.program != "sshd":
            raise UnsupportedEventError(
                f"Linux program {payload.program!r} is not supported"
            )

        if payload.result == "accepted":
            event_type = EventType.AUTHENTICATION_SUCCESS
            outcome = AuthenticationOutcome.SUCCESS
        elif payload.result == "failed":
            event_type = EventType.AUTHENTICATION_FAILURE
            outcome = AuthenticationOutcome.FAILURE
        else:
            raise UnsupportedEventError(
                f"Linux SSH result {payload.result!r} is not supported"
            )

        return SecurityEvent(
            event_id=stable_event_id(self.source_type, envelope.record_id),
            timestamp=payload.timestamp.astimezone(UTC),
            event_type=event_type,
            source=self.source_type,
            username=payload.user,
            source_ip=str(payload.remote_addr),
            outcome=outcome,
            host=payload.hostname,
            attributes={
                "service": payload.program,
                "remote_port": payload.remote_port,
                "authentication_method": payload.authentication_method,
                "message": payload.message,
            },
            source_record_id=envelope.record_id,
        )


class LinuxAuditPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: datetime
    hostname: str = Field(min_length=1)
    record_type: Literal["EXECVE", "USER_CMD", "PATH", "SERVICE_START"]
    user: str | None = None
    executable: str | None = None
    command_line: str | None = None
    target_user: str | None = None
    path: str | None = None
    action: str | None = None
    service_name: str | None = None
    service_path: str | None = None

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value


class LinuxAuditNormalizer:
    source_type = "linux.auditd"

    def normalize(self, envelope: RawEventEnvelope) -> SecurityEvent:
        payload = LinuxAuditPayload.model_validate(envelope.payload)
        attributes: dict[str, JsonValue]
        if (
            payload.record_type == "EXECVE"
            and payload.executable
            and payload.command_line
        ):
            event_type = EventType.PROCESS_START
            attributes = {
                "record_type": payload.record_type,
                "process_name": payload.executable,
                "command_line": payload.command_line,
            }
        elif payload.record_type == "USER_CMD" and payload.command_line:
            event_type = EventType.PRIVILEGE_USE
            attributes = {
                "record_type": payload.record_type,
                "command_line": payload.command_line,
                "target_user": payload.target_user,
            }
        elif payload.record_type == "PATH" and payload.path and payload.action:
            event_type = EventType.FILE_CHANGE
            attributes = {
                "record_type": payload.record_type,
                "path": payload.path,
                "action": payload.action,
            }
        elif (
            payload.record_type == "SERVICE_START"
            and payload.service_name
            and payload.service_path
        ):
            event_type = EventType.SERVICE_INSTALL
            attributes = {
                "record_type": payload.record_type,
                "service_name": payload.service_name,
                "service_path": payload.service_path,
            }
        else:
            raise UnsupportedEventError(
                f"Linux audit record {payload.record_type!r} is missing required fields"
            )
        return SecurityEvent(
            event_id=stable_event_id(self.source_type, envelope.record_id),
            timestamp=payload.timestamp.astimezone(UTC),
            event_type=event_type,
            source=self.source_type,
            username=payload.user,
            source_ip=None,
            outcome=None,
            host=payload.hostname,
            attributes=attributes,
            source_record_id=envelope.record_id,
        )
