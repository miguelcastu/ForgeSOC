from collections.abc import Iterable

from forgesoc.detection.base import Detector
from forgesoc.detection.behavioral import (
    CredentialDumpingDetector,
    DnsBeaconingDetector,
    LinuxSudoDetector,
    PasswordSprayingDetector,
    ServicePersistenceDetector,
    SuspiciousPowerShellDetector,
)
from forgesoc.detection.brute_force import BruteForceDetector
from forgesoc.detection.catalog import DetectionMetadata

DETECTOR_TYPES = (
    BruteForceDetector,
    PasswordSprayingDetector,
    SuspiciousPowerShellDetector,
    CredentialDumpingDetector,
    LinuxSudoDetector,
    ServicePersistenceDetector,
    DnsBeaconingDetector,
)


def default_detectors() -> Iterable[Detector]:
    return [detector_type() for detector_type in DETECTOR_TYPES]


def detection_catalog() -> tuple[DetectionMetadata, ...]:
    return tuple(detector_type.metadata for detector_type in DETECTOR_TYPES)


def metadata_for_rule(rule_id: str) -> DetectionMetadata | None:
    return next(
        (metadata for metadata in detection_catalog() if metadata.rule_id == rule_id),
        None,
    )
