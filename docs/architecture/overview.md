# Sprint 1 architecture

## Data flow

```text
JSONL file -> read_events() -> SecurityEvent -> DetectionEngine
                                               |
                                               v
                                      BruteForceDetector
                                               |
                                               v
                         JSONL file <- write_alerts() <- Alert
```

Sprint 1 is a synchronous monolith. The boundaries are intentionally explicit
so they can be tested independently without introducing services or frameworks.

## Module responsibilities

| Module | Responsibility | Called by | Calls |
| --- | --- | --- | --- |
| `domain/models.py` | Defines immutable events, alerts, and controlled vocabularies. | Ingestion, detection, output, tests | Standard library |
| `ingestion/jsonl.py` | Parses each JSONL record and yields a typed event. | Application entry point, tests | Domain models |
| `detection/base.py` | Defines the structural contract every detector must satisfy. | Detection engine, type checkers | Domain models |
| `detection/engine.py` | Sends every event through each configured detector and yields alerts. | Application entry point, tests | Detectors through their protocol |
| `detection/brute_force.py` | Owns brute-force state, time windows, suppression, and alert creation. | Detection engine, unit tests | Domain models |
| `output/jsonl.py` | Serializes alerts as one JSON object per line. | Application entry point, tests | Domain models |
| `main.py` | Composes the complete pipeline and exposes its command-line interface. | `forgesoc` console command | Ingestion, engine, detector, output |

## Concepts introduced

### Domain models and dataclasses

`SecurityEvent` and `Alert` model the language of the application. They are
frozen dataclasses, so Python generates their routine constructor and comparison
behavior while preventing accidental mutation after creation.

### StrEnum and typing

Enums constrain values such as outcomes and severity. Type hints document and
check which objects cross each boundary, reducing reliance on undocumented
dictionaries inside the application.

### Protocol

`Detector` is a `Protocol`: any object with a compatible `process(event)` method
can be used by the engine. A detector does not need to inherit from a shared
base class. This is structural typing.

### Iterable, Iterator, generators, and yield

Ingestion and detection operate lazily. `read_events()` yields events one by
one, and the engine yields alerts as detectors create them. `yield from` passes
each detector's alerts to the caller without building an intermediate list for
the complete dataset.

### Stateful detection and sliding windows

The brute-force detector remembers failures per `(username, source_ip)` key.
`defaultdict(deque)` creates a queue automatically for a new key. A `deque`
makes removal of expired events from the left efficient. Only failures inside
the current 60-second window count toward the threshold.

### Alert suppression

Once a key has alerted, continued failures in the same burst do not create an
alert for every event. A successful login resets the state. If old failures
expire and the count drops below the threshold, a future burst may alert again.

## Intentional limitations

- Events are assumed to arrive in timestamp order.
- Only the current canonical authentication schema is accepted.
- Detection state exists only in process memory.
- Output replaces the target file on every execution.
- Processing is synchronous and single-process.
- Validation stops at the first malformed event.

These are explicit Sprint 1 tradeoffs, not hidden production claims. Later
sprints should change them only when a demonstrated requirement justifies it.

## Sprint 2 telemetry simulation

```text
Scenario -> TelemetryGenerator -> SecurityEvent stream -> JSONL dataset
                                      |
                                      v
                               Detection pipeline
```

| Module | Responsibility |
| --- | --- |
| `simulation/base.py` | Defines the structural `Scenario` contract. |
| `simulation/entities.py` | Contains fictional users, hosts, reserved IPs, and safe domains. |
| `simulation/generator.py` | Owns seeded randomness, simulated time, and deterministic IDs. |
| `simulation/scenarios.py` | Describes the event sequence and meaning of each scenario. |
| `simulation/jsonl.py` | Serializes events deterministically and protects existing files. |
| `simulation/main.py` | Exposes scenario discovery and generation through a CLI. |

`SecurityEvent` keeps common detection fields explicit and stores event-specific
data in `attributes`. This is a deliberate temporary canonical model, not a
claim that all telemetry sources naturally share one schema. Source-specific
formats and normalization remain future work.

## Sprint 3 normalization

```text
Raw JSONL -> RawRecord -> NormalizationEngine -> source adapter
                                                 |
                      +--------------------------+
                      v
                SecurityEvent v1
                      |
              +-------+--------+
              v                v
      normalized JSONL   DetectionEngine
```

| Module | Responsibility |
| --- | --- |
| `ingestion/raw_jsonl.py` | Preserves raw lines and their file/line provenance. |
| `normalization/schemas.py` | Validates the common raw envelope. |
| `normalization/base.py` | Defines the adapter contract and stable event identity. |
| `normalization/windows_parser.py` | Maps Windows Security authentication records. |
| `normalization/linux_parser.py` | Maps structured Linux SSH records. |
| `normalization/engine.py` | Parses envelopes, selects adapters, and classifies failures. |
| `normalization/models.py` | Represents successes, failures, error codes, and quality reports. |
| `normalization/main.py` | Composes the normalizers and exposes the CLI. |
| `output/events_jsonl.py` | Owns shared canonical-event serialization. |
| `output/rejections_jsonl.py` | Writes safe rejection metadata without raw payloads. |

Pydantic schemas exist only at untrusted external boundaries. The internal
domain remains standard-library dataclasses. Detection therefore consumes one
model regardless of the original provider.
