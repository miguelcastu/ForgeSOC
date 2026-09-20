from collections import defaultdict, deque
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

from forgesoc.detection.catalog import DetectionMetadata, technique
from forgesoc.domain.models import (
    Alert,
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
    Severity,
)


def _text(event: SecurityEvent, key: str) -> str:
    value = event.attributes.get(key)
    return value.lower() if isinstance(value, str) else ""


def _alert(
    metadata: DetectionMetadata,
    triggering_event: SecurityEvent,
    evidence: tuple[SecurityEvent, ...],
    reason: str,
) -> Alert:
    evidence_ids = tuple(event.event_id for event in evidence)
    identity = "\0".join((metadata.rule_id, *evidence_ids))
    return Alert(
        alert_id=str(uuid5(NAMESPACE_URL, identity)),
        timestamp=triggering_event.timestamp,
        rule_id=metadata.rule_id,
        title=metadata.title,
        severity=metadata.severity,
        username=triggering_event.username,
        source_ip=triggering_event.source_ip,
        related_event_ids=evidence_ids,
        reason=reason,
    )


class PasswordSprayingDetector:
    metadata = DetectionMetadata(
        rule_id="AUTH-SPRAY-002",
        title="Possible password spraying",
        description="One source fails authentication against many identities.",
        severity=Severity.HIGH,
        platforms=("Windows", "Linux"),
        log_types=("windows.security", "linux.ssh"),
        event_types=(EventType.AUTHENTICATION_FAILURE,),
        mitre=(
            technique(
                "T1110.003", "Brute Force: Password Spraying", "Credential Access"
            ),
        ),
    )

    def __init__(
        self, threshold: int = 5, window: timedelta = timedelta(minutes=2)
    ) -> None:
        self.threshold = threshold
        self.window = window
        self._events: dict[str, deque[SecurityEvent]] = defaultdict(deque)
        self._alerted: set[str] = set()

    def process(self, event: SecurityEvent) -> list[Alert]:
        if (
            event.event_type != EventType.AUTHENTICATION_FAILURE
            or event.outcome != AuthenticationOutcome.FAILURE
            or event.source_ip is None
            or event.username is None
        ):
            return []
        events = self._events[event.source_ip]
        cutoff = event.timestamp - self.window
        while events and events[0].timestamp < cutoff:
            events.popleft()
        events.append(event)
        usernames = {item.username for item in events}
        if len(usernames) < self.threshold:
            self._alerted.discard(event.source_ip)
            return []
        if event.source_ip in self._alerted:
            return []
        self._alerted.add(event.source_ip)
        evidence = tuple(events)
        return [
            _alert(
                self.metadata,
                event,
                evidence,
                f"{len(usernames)} identities failed from one source within "
                f"{self.window.total_seconds():.0f} seconds",
            )
        ]


class SuspiciousPowerShellDetector:
    metadata = DetectionMetadata(
        rule_id="WIN-POWERSHELL-003",
        title="Suspicious PowerShell execution",
        description="PowerShell uses encoded or download-oriented execution flags.",
        severity=Severity.HIGH,
        platforms=("Windows",),
        log_types=("windows.sysmon", "windows.security"),
        event_types=(EventType.PROCESS_START,),
        mitre=(technique("T1059.001", "PowerShell", "Execution"),),
    )
    _indicators = (
        "-encodedcommand",
        " -enc ",
        "downloadstring",
        "invoke-webrequest",
        "frombase64string",
    )

    def process(self, event: SecurityEvent) -> list[Alert]:
        process = _text(event, "process_name")
        command = _text(event, "command_line")
        if event.event_type != EventType.PROCESS_START:
            return []
        if "powershell" not in process and "pwsh" not in process:
            return []
        matches = [
            indicator.strip() for indicator in self._indicators if indicator in command
        ]
        if not matches:
            return []
        return [
            _alert(
                self.metadata,
                event,
                (event,),
                f"PowerShell command line matched: {', '.join(matches)}",
            )
        ]


class CredentialDumpingDetector:
    metadata = DetectionMetadata(
        rule_id="OS-CREDDUMP-004",
        title="Possible OS credential dumping",
        description="A process references known credential-dumping tools or LSASS.",
        severity=Severity.CRITICAL,
        platforms=("Windows", "Linux"),
        log_types=("windows.sysmon", "windows.security", "linux.auditd"),
        event_types=(EventType.PROCESS_START,),
        mitre=(technique("T1003", "OS Credential Dumping", "Credential Access"),),
    )
    _indicators = (
        "mimikatz",
        "sekurlsa",
        "lsadump",
        "comsvcs.dll",
        "procdump",
        "/etc/shadow",
        "gcore",
    )

    def process(self, event: SecurityEvent) -> list[Alert]:
        if event.event_type != EventType.PROCESS_START:
            return []
        combined = f"{_text(event, 'process_name')} {_text(event, 'command_line')}"
        matches = [indicator for indicator in self._indicators if indicator in combined]
        if not matches:
            return []
        return [
            _alert(
                self.metadata,
                event,
                (event,),
                f"Process execution matched credential access indicator: {matches[0]}",
            )
        ]


class LinuxSudoDetector:
    metadata = DetectionMetadata(
        rule_id="LNX-SUDO-005",
        title="High-risk sudo execution",
        description="Sudo launches a shell or modifies identity and access controls.",
        severity=Severity.HIGH,
        platforms=("Linux",),
        log_types=("linux.auditd",),
        event_types=(EventType.PRIVILEGE_USE,),
        mitre=(
            technique(
                "T1548.003",
                "Abuse Elevation Control Mechanism: Sudo",
                "Privilege Escalation",
            ),
        ),
    )
    _indicators = ("/bin/bash", "/bin/sh", "useradd", "usermod", "chmod u+s")

    def process(self, event: SecurityEvent) -> list[Alert]:
        if event.event_type != EventType.PRIVILEGE_USE:
            return []
        command = _text(event, "command_line")
        target = _text(event, "target_user")
        matches = [indicator for indicator in self._indicators if indicator in command]
        if target != "root" or not matches:
            return []
        return [
            _alert(
                self.metadata,
                event,
                (event,),
                f"sudo to root executed high-risk command containing {matches[0]}",
            )
        ]


class ServicePersistenceDetector:
    metadata = DetectionMetadata(
        rule_id="OS-SERVICE-006",
        title="Suspicious service persistence",
        description="A new service points to a user-writable or temporary path.",
        severity=Severity.HIGH,
        platforms=("Windows", "Linux"),
        log_types=("windows.security", "linux.auditd"),
        event_types=(EventType.SERVICE_INSTALL,),
        mitre=(
            technique("T1543.002", "Systemd Service", "Persistence"),
            technique("T1543.003", "Windows Service", "Persistence"),
        ),
    )
    _paths = ("\\temp\\", "\\users\\public\\", "/tmp/", "/var/tmp/")

    def process(self, event: SecurityEvent) -> list[Alert]:
        if event.event_type != EventType.SERVICE_INSTALL:
            return []
        executable = _text(event, "service_path")
        matches = [path for path in self._paths if path in executable]
        if not matches:
            return []
        return [
            _alert(
                self.metadata,
                event,
                (event,),
                f"Service executable uses suspicious path: {matches[0]}",
            )
        ]


class DnsBeaconingDetector:
    metadata = DetectionMetadata(
        rule_id="NET-DNS-BEACON-007",
        title="Possible DNS beaconing",
        description="A host repeatedly queries the same uncommon domain.",
        severity=Severity.MEDIUM,
        platforms=("Windows", "Linux"),
        log_types=("windows.sysmon", "dns.sensor"),
        event_types=(EventType.DNS_QUERY,),
        mitre=(
            technique(
                "T1071.004", "Application Layer Protocol: DNS", "Command and Control"
            ),
        ),
    )

    def __init__(
        self, threshold: int = 5, window: timedelta = timedelta(minutes=5)
    ) -> None:
        self.threshold = threshold
        self.window = window
        self._events: dict[tuple[str, str], deque[SecurityEvent]] = defaultdict(deque)
        self._alerted: set[tuple[str, str]] = set()

    def process(self, event: SecurityEvent) -> list[Alert]:
        domain = _text(event, "query")
        host = event.host or event.source_ip
        if event.event_type != EventType.DNS_QUERY or not domain or host is None:
            return []
        key = (host, domain)
        events = self._events[key]
        cutoff = event.timestamp - self.window
        while events and events[0].timestamp < cutoff:
            events.popleft()
        events.append(event)
        if len(events) < self.threshold:
            self._alerted.discard(key)
            return []
        if key in self._alerted:
            return []
        self._alerted.add(key)
        return [
            _alert(
                self.metadata,
                event,
                tuple(events),
                f"{len(events)} DNS queries for {domain} within five minutes",
            )
        ]
