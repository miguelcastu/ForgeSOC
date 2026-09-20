# Sprint 7: Threat-informed detection coverage

## Goal

Expand ForgeSOC from one authentication analytic into a threat-informed Windows
and Linux detection lab with realistic telemetry, MITRE ATT&CK traceability,
visible coverage, and explicit gaps.

## Delivered

- Seven enabled detection rules covering authentication, execution, credential
  access, privilege escalation, persistence, and DNS command and control.
- Typed rule metadata with platforms, log types, canonical event types,
  severity, and MITRE ATT&CK techniques.
- Password spraying, suspicious PowerShell, credential dumping, risky sudo,
  suspicious services, and DNS beaconing analytics.
- Windows Security 4688/4697 and Sysmon 1/3/22 normalization.
- Linux auditd EXECVE, USER_CMD, PATH, and SERVICE_START normalization.
- Five additional attack-focused scenarios plus cross-platform service variants.
- Scenario profiles that state event counts, event types, and expected rule IDs.
- Raw Windows and Linux activity datasets for import demonstrations.
- Authenticated `/api/v1/coverage` endpoint and web coverage matrix.
- A complete Windows/Linux threat model and detection-engineering workflow.

## Acceptance criteria

- Normal activity remains alert-free.
- Every malicious scenario fires its expected stable rule ID.
- All enabled rules have MITRE mapping and required log source metadata.
- Coverage derives from the executable detector registry.
- Raw Windows/Linux activity normalizes without rejection.
- Ruff, mypy, migrations, tests, build, and Docker smoke checks pass.
