import argparse
from pathlib import Path

from forgesoc.detection.brute_force import (
    BruteForceDetector,
)
from forgesoc.detection.engine import (
    DetectionEngine,
)
from forgesoc.ingestion.jsonl import (
    read_events,
)
from forgesoc.output.jsonl import (
    write_alerts,
)


def run(
    input_path: Path,
    output_path: Path,
) -> int:
    events = read_events(
        input_path
    )

    engine = DetectionEngine(
        detectors=[
            BruteForceDetector(),
        ]
    )

    alerts = engine.process(
        events
    )

    return write_alerts(
        alerts=alerts,
        path=output_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "ForgeSOC Detection Platform"
        )
    )

    parser.add_argument(
        "input",
        type=Path,
        help=(
            "Path to the JSONL "
            "security events file"
        ),
    )

    parser.add_argument(
        "output",
        type=Path,
        help=(
            "Path where alerts "
            "will be written"
        ),
    )

    args = parser.parse_args()

    alert_count = run(
        input_path=args.input,
        output_path=args.output,
    )

    print(
        f"ForgeSOC generated "
        f"{alert_count} alert(s)."
    )


if __name__ == "__main__":
    main()