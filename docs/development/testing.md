# Testing and quality checks

## Complete local verification

```powershell
uv sync
uv run ruff check .
uv run mypy
uv run pytest -v
uv run forgesoc data/security_events.jsonl data/alerts.jsonl
```

## Test layers

- `tests/test_brute_force.py` isolates detector behavior and its state changes.
- `tests/test_pipeline.py` exercises ingestion, detection, and output together
  using the committed synthetic dataset and a temporary output file.
- `tests/test_simulation.py` verifies deterministic generation, event contracts,
  scenario meaning, overwrite protection, JSONL round trips, and current
  detection results.
- `tests/test_normalization.py` verifies source mappings, validation failures,
  stable identity, UTC conversion, rejection policy, quality reports, and raw
  Windows/Linux telemetry replayed through detection.

Tests must be deterministic: fixed timestamps and synthetic identities make
failures reproducible. A detection change should include positive and negative
cases and must not rely on network services.

## Ruff

Ruff enforces the rule sets configured in `pyproject.toml`. Run it before every
commit. Automatic fixes can be reviewed with:

```powershell
uv run ruff check . --fix
git diff
```

## Static type checking

```powershell
uv run mypy
```

ForgeSOC publishes the `py.typed` marker so its annotations are available when
the installed package is checked. Mypy runs in strict mode over application
code and is also required by CI.
