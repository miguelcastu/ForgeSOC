from dataclasses import dataclass

from forgesoc.domain.models import EventType, Severity


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    url: str


@dataclass(frozen=True, slots=True)
class DetectionMetadata:
    rule_id: str
    title: str
    description: str
    severity: Severity
    platforms: tuple[str, ...]
    log_types: tuple[str, ...]
    event_types: tuple[EventType, ...]
    mitre: tuple[MitreTechnique, ...]


def technique(technique_id: str, name: str, tactic: str) -> MitreTechnique:
    path = technique_id.replace(".", "/")
    return MitreTechnique(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        url=f"https://attack.mitre.org/techniques/{path}/",
    )
