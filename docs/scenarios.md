# Synthetic scenario catalog

All identities are fictional. Public IP addresses use documentation ranges and
domains use reserved suffixes. Scenario output is canonical synthetic telemetry,
not an exact copy of a vendor log format.

## Common controls

- `--seed`: controls deterministic choices.
- `--start-time`: sets a timezone-aware ISO 8601 starting point.
- `--output`: selects the JSONL destination.
- `--force`: explicitly permits replacing an existing file.

## `normal-activity`

Seven benign Windows/Linux events covering successful authentication, an
isolated failed login, process start, DNS, network, and HTTP activity.

Expected current alerts: **0**.

## `brute-force`

Six authentication failures for one username and source IP within 60 seconds.

Expected current alerts: **1** (`AUTH-BRUTEFORCE-001`).

## `brute-force-then-success`

Five failures followed by a successful login for the same identity and IP. It
demonstrates an alert followed by state reset and provides future correlation
data for a possible account-compromise sequence.

Expected current alerts: **1**.

## `suspicious-powershell`

A synthetic Word process launches PowerShell with `-EncodedCommand`. The encoded
value contains a harmless ForgeSOC test marker, not an executable payload.

Expected current alerts: **0** until a process detector is implemented.

## `malicious-domain`

DNS resolution, outbound network connection, and HTTP request share a
`correlation_id`. The domain and destination IP are reserved for testing.

Expected current alerts: **0** until network detections are implemented.

## `credential-spraying`

One source IP attempts one authentication against eight different users. It is
deliberately a negative case for the current detector, which groups failures by
both username and source IP.

Expected current alerts: **0**. The dataset motivates a future spraying rule.
