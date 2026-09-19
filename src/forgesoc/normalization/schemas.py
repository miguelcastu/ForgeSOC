from pydantic import BaseModel, ConfigDict, Field

from forgesoc.domain.models import JsonValue


class RawEventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: str = Field(min_length=1)
    record_id: str = Field(min_length=1)
    payload: dict[str, JsonValue]
