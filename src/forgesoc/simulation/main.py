import argparse
from datetime import UTC, datetime
from pathlib import Path

from forgesoc.simulation.generator import TelemetryGenerator
from forgesoc.simulation.jsonl import write_events
from forgesoc.simulation.scenarios import SCENARIOS, get_scenario

DEFAULT_START_TIME = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


def parse_start_time(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("start time must be ISO 8601") from exc

    if timestamp.tzinfo is None:
        raise argparse.ArgumentTypeError("start time must include a timezone")

    return timestamp


def run_generation(
    scenario_name: str,
    output_path: Path,
    *,
    seed: int = 42,
    start_time: datetime = DEFAULT_START_TIME,
    overwrite: bool = False,
) -> int:
    scenario = get_scenario(scenario_name)
    generator = TelemetryGenerator(scenario.name, seed, start_time)
    return write_events(
        scenario.generate(generator),
        output_path,
        overwrite=overwrite,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate deterministic synthetic telemetry for ForgeSOC."
    )
    parser.add_argument("--scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--start-time",
        type=parse_start_time,
        default=DEFAULT_START_TIME,
        help="Timezone-aware ISO 8601 timestamp.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace the output file if it already exists.",
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List available scenarios and exit.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_scenarios:
        for name, scenario in sorted(SCENARIOS.items()):
            print(f"{name}: {scenario.description}")
        return

    if args.scenario is None or args.output is None:
        parser.error(
            "--scenario and --output are required unless --list-scenarios is used"
        )

    try:
        event_count = run_generation(
            args.scenario,
            args.output,
            seed=args.seed,
            start_time=args.start_time,
            overwrite=args.force,
        )
    except FileExistsError as exc:
        parser.error(f"{exc}. Use --force to replace it.")

    print(f"ForgeSOC generated {event_count} synthetic event(s).")


if __name__ == "__main__":
    main()
