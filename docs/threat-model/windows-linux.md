# Windows and Linux detection threat model

## Purpose and scope

This threat model turns security concerns into testable telemetry and detection
hypotheses for ForgeSOC. It covers synthetic Windows workstations and Linux
servers from initial access through execution, credential access, privilege
escalation, persistence, and command and control. It does not claim complete
MITRE ATT&CK coverage or model cloud, identity-provider, container, firmware,
physical, or supply-chain threats.

The exercise answers four detection-engineering questions:

1. Which assets and security properties matter?
2. How could an adversary cross a trust boundary or abuse an asset?
3. Which observable events would support or disprove that hypothesis?
4. Which tested rule, investigation evidence, and known gap result?

## Assets and security objectives

| Asset | Why it matters | Security objectives |
| --- | --- | --- |
| User and service credentials | Enable access and lateral movement | Confidentiality, controlled use, rapid abuse detection |
| Windows workstations | Hold user sessions and execution tooling | Execution integrity, persistence visibility |
| Linux servers | Host applications and privileged services | Privilege integrity, change accountability |
| Authentication services | Decide who can enter systems | Availability, integrity, brute-force visibility |
| Processes and command lines | Show execution intent | Complete, untampered telemetry |
| Services and startup configuration | Survive reboot and run privileged code | Authorized change, persistence detection |
| DNS and network activity | Connect endpoints to external systems | Destination visibility, C2 detection |
| Security telemetry | Evidence for detections and investigations | Integrity, provenance, ordering, retention |
| Detection rules and metadata | Convert observations into findings | Testability, traceability, explainability |
| Analyst accounts and cases | Control and document response decisions | Authentication, authorization, auditability |

## Trust boundaries and data flow

```text
external network
      |
      | authentication / DNS / outbound traffic
      v
Windows endpoint ----- local admin boundary ----- Windows service control
      |  Security 4624/4625/4688/4697 + Sysmon 1/3/22
      |
      +-------------------- telemetry boundary -------------------+
                                                                 |
Linux server -------- sudo/root boundary -------- systemd/files  |
      |  SSH + auditd EXECVE/USER_CMD/PATH/SERVICE_START          |
      |                                                          v
      +----------------------------------------------> normalization
                                                           |
                                                           v
                                                    canonical events
                                                           |
                                                storage -> detection -> case
```

Endpoint logs are untrusted input: they may be missing, malformed, delayed, or
attacker-influenced. Normalization validates them before they cross into the
canonical domain. Analyst actions cross a separate authorization boundary and
are audited.

## Threat actors and assumptions

- An external attacker can attempt remote authentication and communicate with
  controlled infrastructure.
- A compromised user can execute commands but does not initially have local
  administrator or root privileges.
- An insider or post-exploitation actor may know legitimate tools and paths.
- Endpoint logging is configured and delivered; ForgeSOC cannot detect events
  that the source never records or an attacker successfully suppresses.
- All repository data is synthetic. Rules demonstrate engineering technique,
  not production-ready tuning for every environment.

## Threat analysis and detection hypotheses

| Threat / abused asset | MITRE ATT&CK | Required telemetry | Detection hypothesis | ForgeSOC rule |
| --- | --- | --- | --- | --- |
| Guess many passwords for one identity | T1110.001 Password Guessing | Windows 4625 or Linux SSH failures | Five failures for the same user and source in 60 seconds are suspicious | `AUTH-BRUTEFORCE-001` |
| Reuse one password across many identities | T1110.003 Password Spraying | Windows/Linux authentication failures | One source failing against five identities in two minutes indicates spraying | `AUTH-SPRAY-002` |
| Use encoded/download-capable PowerShell | T1059.001 PowerShell | Security 4688 or Sysmon 1 command line | PowerShell with encoded or download indicators is high-risk execution | `WIN-POWERSHELL-003` |
| Extract secrets from LSASS or OS stores | T1003 OS Credential Dumping | Windows/Linux process execution | Dumping tools, LSASS references, or `/etc/shadow` access indicate credential access | `OS-CREDDUMP-004` |
| Obtain a privileged Linux shell through sudo | T1548.003 Sudo and Sudo Caching | auditd `USER_CMD` | A root shell or identity-changing command through sudo deserves investigation | `LNX-SUDO-005` |
| Install a service from a writable path | T1543.002 Systemd Service / T1543.003 Windows Service | Windows 4697 or auditd service record | A service binary under temp or public user paths is suspicious persistence | `OS-SERVICE-006` |
| Repeatedly communicate over DNS | T1071.004 DNS | Sysmon 22 or DNS sensor | Five same-domain queries in five minutes may be beaconing | `NET-DNS-BEACON-007` |

Technique names and identifiers link to the official MITRE ATT&CK pages from
the API and web coverage view.

## Platform-specific attack surface

### Windows

- Remote and interactive logons expose password guessing and spraying.
- Office processes, PowerShell, command shells, and signed utilities provide
  execution paths that can blend with administration.
- LSASS and related credential stores are valuable post-compromise targets.
- Service Control Manager changes can establish persistence with SYSTEM rights.
- Sysmon process, network, and DNS events improve context beyond Security logs.

### Linux

- SSH is an externally reachable authentication boundary.
- `sudo`, setuid behavior, and root shells are privilege-escalation paths.
- `/etc`, cron, systemd, SSH keys, and shell startup files are persistence and
  configuration targets.
- auditd command, path, and service records provide execution and change
  evidence, but require intentional rules on the endpoint.
- DNS and outbound traffic can carry command-and-control regardless of OS.

## Detection engineering workflow used

1. **Define scope and assets.** State the systems, identities, evidence, and
   security properties being protected.
2. **Draw trust boundaries.** Identify external input, privilege changes,
   endpoint collection, normalization, and analyst-control boundaries.
3. **Enumerate threats.** Use attacker goals and ATT&CK behavior, not only tool
   names, to produce realistic abuse cases.
4. **Write a hypothesis.** Express an observable statement with entity,
   behavior, time window, and expected rarity.
5. **Map telemetry.** Name the provider, event identifiers, required fields,
   normalization mapping, and likely collection failure modes.
6. **Implement an explainable analytic.** Emit stable identity, severity,
   ordered evidence, platforms, log sources, and MITRE mapping.
7. **Generate malicious and benign data.** Keep scenarios deterministic so a
   failure is reproducible and normal activity catches obvious false positives.
8. **Validate end to end.** Test normalization, rule boundaries, suppression,
   persistence, API contracts, evidence, and coverage.
9. **Measure coverage and gaps.** Data without a rule is a detection gap; a
   rule without incoming data is a collection gap.
10. **Tune with feedback.** Analyst dispositions should later drive reviewed
    threshold, allow-list, and severity changes.

## Validation evidence

- Every malicious scenario declares the rule IDs expected to fire in the API.
- Unit tests cover each analytic and confirm benign activity remains quiet.
- Raw Windows/Linux samples test source validation and canonical conversion.
- PostgreSQL integration tests verify the API coverage catalog and MITRE links.
- Alert IDs remain deterministic from rule ID plus ordered evidence.
- The coverage page uses the executable detector registry, preventing drift.

## Known gaps and next priorities

| Gap | Risk | Recommended next step |
| --- | --- | --- |
| File-change events have no behavioral rule | Cron, SSH key, and shell-profile persistence can be missed | Add path-aware persistence analytics and baselines |
| No process ancestry graph | Single-event PowerShell logic lacks chain context | Persist process and parent GUIDs and correlate trees |
| DNS rule uses a simple threshold | Popular domains or resolver retries may be noisy | Add rarity, allow-lists, entropy, and interval scoring |
| No telemetry-health monitoring | Missing endpoint logs can look like normal silence | Track last-seen, volume baselines, and agent health |
| No Windows registry telemetry | Run keys and security-control changes are uncovered | Add Sysmon registry events and new hypotheses |
| No Linux kernel/eBPF context | Short-lived or tampered processes may be missed | Evaluate complementary runtime sensors |
| Static local indicators | Tool renaming can bypass name-based rules | Add access, signature, ancestry, and behavior correlation |
| ATT&CK mapping is manually reviewed | Framework updates may make metadata stale | Add periodic catalog review and version tracking |

The gaps are intentional output of the model, not hidden limitations. They
form the prioritized backlog for future detection sprints.
