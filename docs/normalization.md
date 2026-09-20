# Normalization mappings

## Raw envelope

Every input line is a JSON object with:

| Field | Meaning |
| --- | --- |
| `source_type` | Adapter selector such as `windows.security`. |
| `record_id` | Stable identity assigned by the source. |
| `payload` | Provider-specific event fields. |

The normalized event retains `source_type` as `source` and `record_id` as
`source_record_id`. Its `event_id` is a deterministic SHA-256-derived identifier
scoped by both values.

## Windows Security

Supported source: `windows.security`.

| Raw field | Canonical field |
| --- | --- |
| `EventID=4624` | `event_type=authentication.success`, `outcome=success` |
| `EventID=4625` | `event_type=authentication.failure`, `outcome=failure` |
| `EventID=4688` | `event_type=process.start` plus process and parent command data |
| `EventID=4697` | `event_type=service.install` plus service path and start type |
| `TimeCreated` | `timestamp`, converted to UTC |
| `Computer` | `host` |
| `TargetUserName` | `username` |
| `IpAddress` | `source_ip` |
| `LogonType` | `attributes.logon_type` |
| `AuthenticationPackageName` | `attributes.authentication_package` |
| `Status`, `SubStatus` | Source-specific attributes |

Other Windows event codes are reported as `unsupported_event` rather than
being guessed or silently discarded.

## Windows Sysmon

Supported source: `windows.sysmon`.

| Event | Canonical event |
| --- | --- |
| Event ID 1 | `process.start` |
| Event ID 3 | `network.connection` |
| Event ID 22 | `dns.query` |

The adapter preserves image, command line, parent image, source/destination
address, destination port, and DNS query fields when relevant.

## Linux SSH

Supported source: `linux.ssh`.

| Raw field | Canonical field |
| --- | --- |
| `result=accepted` | `event_type=authentication.success`, `outcome=success` |
| `result=failed` | `event_type=authentication.failure`, `outcome=failure` |
| `timestamp` | `timestamp`, converted to UTC |
| `hostname` | `host` |
| `user` | `username` |
| `remote_addr` | `source_ip` |
| `program` | `attributes.service` |
| `remote_port` | `attributes.remote_port` |
| `authentication_method` | Source-specific attribute |

Only structured `sshd` records are supported. Parsing unstructured syslog text
is intentionally outside the current sprint.

## Linux auditd

Supported source: `linux.auditd`.

| Structured record | Canonical event |
| --- | --- |
| `EXECVE` | `process.start` |
| `USER_CMD` | `privilege.use` |
| `PATH` | `file.change` |
| `SERVICE_START` | `service.install` |

The educational adapter expects already-structured audit fields. Joining raw
multi-record audit messages and parsing arbitrary syslog text remain explicit
collection-layer responsibilities.

## Error handling

| Error code | Meaning |
| --- | --- |
| `invalid_json` | The line is not valid JSON. |
| `invalid_record` | The JSON value is not an object. |
| `missing_field` | A required envelope or payload field is absent. |
| `invalid_field` | A field has an invalid type, IP, timestamp, or value. |
| `unsupported_source` | No adapter is registered for the source. |
| `unsupported_event` | The source is known but that activity is not supported. |

Strict mode stops before writing normalized output. Continue mode requires a
rejection path, processes remaining records, and reports data-quality counts.
