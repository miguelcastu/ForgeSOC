from collections.abc import Iterable

from forgesoc.domain.models import (
    AuthenticationOutcome,
    EventType,
    SecurityEvent,
)
from forgesoc.simulation.base import Scenario
from forgesoc.simulation.entities import (
    BENIGN_DOMAINS,
    DOCUMENTATION_IPS,
    INTERNAL_IPS,
    LINUX_HOSTS,
    SUSPICIOUS_DOMAIN,
    SUSPICIOUS_IP,
    USERS,
    WINDOWS_HOSTS,
)
from forgesoc.simulation.generator import TelemetryGenerator


class NormalActivityScenario:
    name = "normal-activity"
    description = "Benign authentication, process, DNS, network, and HTTP activity."

    def generate(
        self,
        generator: TelemetryGenerator,
    ) -> Iterable[SecurityEvent]:
        user = generator.choice(USERS)
        source_ip = generator.choice(INTERNAL_IPS)
        windows_host = generator.choice(WINDOWS_HOSTS)
        linux_host = generator.choice(LINUX_HOSTS)
        domain = generator.choice(BENIGN_DOMAINS)

        yield generator.event(
            EventType.AUTHENTICATION_SUCCESS,
            "windows.eventlog",
            username=user,
            source_ip=source_ip,
            outcome=AuthenticationOutcome.SUCCESS,
            host=windows_host,
            attributes={"logon_type": 2, "authentication_package": "Kerberos"},
        )
        yield generator.event(
            EventType.PROCESS_START,
            "windows.sysmon",
            after_seconds=4,
            username=user,
            host=windows_host,
            attributes={
                "process_name": "explorer.exe",
                "process_id": 4120,
                "parent_process": "userinit.exe",
                "command_line": "C:\\Windows\\Explorer.EXE",
            },
        )
        yield generator.event(
            EventType.DNS_QUERY,
            "dns.sensor",
            after_seconds=3,
            source_ip=source_ip,
            host=windows_host,
            attributes={"query": domain, "query_type": "A", "response_code": "NOERROR"},
        )
        yield generator.event(
            EventType.NETWORK_CONNECTION,
            "network.sensor",
            after_seconds=1,
            source_ip=source_ip,
            host=windows_host,
            attributes={
                "destination_ip": "192.0.2.20",
                "destination_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
            },
        )
        yield generator.event(
            EventType.HTTP_REQUEST,
            "proxy",
            after_seconds=1,
            source_ip=source_ip,
            host=windows_host,
            attributes={
                "method": "GET",
                "url": f"https://{domain}/index.html",
                "status_code": 200,
                "user_agent": "ForgeSOC-Synthetic-Browser/1.0",
            },
        )
        yield generator.event(
            EventType.AUTHENTICATION_FAILURE,
            "linux.auth",
            after_seconds=18,
            username=generator.choice(USERS),
            source_ip=generator.choice(INTERNAL_IPS),
            outcome=AuthenticationOutcome.FAILURE,
            host=linux_host,
            attributes={"service": "sshd", "reason": "invalid_password"},
        )
        yield generator.event(
            EventType.AUTHENTICATION_SUCCESS,
            "linux.auth",
            after_seconds=8,
            username=generator.choice(USERS),
            source_ip=generator.choice(INTERNAL_IPS),
            outcome=AuthenticationOutcome.SUCCESS,
            host=linux_host,
            attributes={"service": "sshd", "method": "publickey"},
        )


class BruteForceScenario:
    name = "brute-force"
    description = "Repeated failures for one username and source IP."

    def generate(
        self,
        generator: TelemetryGenerator,
    ) -> Iterable[SecurityEvent]:
        user = generator.choice(USERS)
        source_ip = generator.choice(DOCUMENTATION_IPS)
        host = generator.choice(WINDOWS_HOSTS)

        for attempt in range(1, 7):
            yield generator.event(
                EventType.AUTHENTICATION_FAILURE,
                "windows.eventlog",
                after_seconds=0 if attempt == 1 else 8,
                username=user,
                source_ip=source_ip,
                outcome=AuthenticationOutcome.FAILURE,
                host=host,
                attributes={
                    "event_code": 4625,
                    "logon_type": 10,
                    "attempt": attempt,
                    "reason": "invalid_password",
                },
            )


class BruteForceThenSuccessScenario:
    name = "brute-force-then-success"
    description = "Brute-force threshold followed by a successful login."

    def generate(
        self,
        generator: TelemetryGenerator,
    ) -> Iterable[SecurityEvent]:
        user = generator.choice(USERS)
        source_ip = generator.choice(DOCUMENTATION_IPS)
        host = generator.choice(LINUX_HOSTS)

        for attempt in range(1, 6):
            yield generator.event(
                EventType.AUTHENTICATION_FAILURE,
                "linux.auth",
                after_seconds=0 if attempt == 1 else 9,
                username=user,
                source_ip=source_ip,
                outcome=AuthenticationOutcome.FAILURE,
                host=host,
                attributes={
                    "service": "sshd",
                    "attempt": attempt,
                    "reason": "invalid_password",
                },
            )

        yield generator.event(
            EventType.AUTHENTICATION_SUCCESS,
            "linux.auth",
            after_seconds=7,
            username=user,
            source_ip=source_ip,
            outcome=AuthenticationOutcome.SUCCESS,
            host=host,
            attributes={"service": "sshd", "method": "password"},
        )


class SuspiciousPowerShellScenario:
    name = "suspicious-powershell"
    description = "Office-spawned PowerShell with a synthetic encoded command."

    def generate(
        self,
        generator: TelemetryGenerator,
    ) -> Iterable[SecurityEvent]:
        user = generator.choice(USERS)
        host = generator.choice(WINDOWS_HOSTS)

        yield generator.event(
            EventType.PROCESS_START,
            "windows.sysmon",
            username=user,
            host=host,
            attributes={
                "process_name": "WINWORD.EXE",
                "process_id": 6200,
                "parent_process": "explorer.exe",
                "command_line": "WINWORD.EXE synthetic-report.docm",
            },
        )
        yield generator.event(
            EventType.PROCESS_START,
            "windows.sysmon",
            after_seconds=2,
            username=user,
            host=host,
            attributes={
                "process_name": "powershell.exe",
                "process_id": 6244,
                "parent_process": "WINWORD.EXE",
                "command_line": (
                    "powershell.exe -NoProfile -EncodedCommand "
                    "U3ludGhldGljLUZvcmdlU09DLVRlc3Q="
                ),
                "integrity_level": "medium",
            },
        )


class MaliciousDomainScenario:
    name = "malicious-domain"
    description = "Correlated DNS, network, and HTTP activity to a test domain."

    def generate(
        self,
        generator: TelemetryGenerator,
    ) -> Iterable[SecurityEvent]:
        source_ip = generator.choice(INTERNAL_IPS)
        host = generator.choice(WINDOWS_HOSTS)
        correlation_id = "synthetic-domain-chain-001"

        yield generator.event(
            EventType.DNS_QUERY,
            "dns.sensor",
            source_ip=source_ip,
            host=host,
            attributes={
                "query": SUSPICIOUS_DOMAIN,
                "query_type": "A",
                "answers": [SUSPICIOUS_IP],
                "response_code": "NOERROR",
                "correlation_id": correlation_id,
            },
        )
        yield generator.event(
            EventType.NETWORK_CONNECTION,
            "network.sensor",
            after_seconds=1,
            source_ip=source_ip,
            host=host,
            attributes={
                "destination_ip": SUSPICIOUS_IP,
                "destination_port": 443,
                "protocol": "tcp",
                "direction": "outbound",
                "correlation_id": correlation_id,
            },
        )
        yield generator.event(
            EventType.HTTP_REQUEST,
            "proxy",
            after_seconds=1,
            source_ip=source_ip,
            host=host,
            attributes={
                "method": "POST",
                "url": f"https://{SUSPICIOUS_DOMAIN}/beacon",
                "status_code": 200,
                "user_agent": "ForgeSOC-Synthetic-Agent/1.0",
                "correlation_id": correlation_id,
            },
        )


class CredentialSprayingScenario:
    name = "credential-spraying"
    description = "One source IP attempts a password against many usernames."

    def generate(
        self,
        generator: TelemetryGenerator,
    ) -> Iterable[SecurityEvent]:
        source_ip = generator.choice(DOCUMENTATION_IPS)
        host = generator.choice(WINDOWS_HOSTS)

        for attempt, user in enumerate(USERS, start=1):
            yield generator.event(
                EventType.AUTHENTICATION_FAILURE,
                "windows.eventlog",
                after_seconds=0 if attempt == 1 else 6,
                username=user,
                source_ip=source_ip,
                outcome=AuthenticationOutcome.FAILURE,
                host=host,
                attributes={
                    "event_code": 4625,
                    "logon_type": 3,
                    "spray_round": 1,
                    "reason": "invalid_password",
                },
            )


SCENARIOS: dict[str, Scenario] = {
    scenario.name: scenario
    for scenario in (
        NormalActivityScenario(),
        BruteForceScenario(),
        BruteForceThenSuccessScenario(),
        SuspiciousPowerShellScenario(),
        MaliciousDomainScenario(),
        CredentialSprayingScenario(),
    )
}


def get_scenario(name: str) -> Scenario:
    try:
        return SCENARIOS[name]
    except KeyError as exc:
        available = ", ".join(sorted(SCENARIOS))
        raise ValueError(f"Unknown scenario {name!r}. Available: {available}") from exc
