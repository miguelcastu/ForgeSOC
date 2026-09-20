import argparse
from collections.abc import Mapping
from pathlib import Path

from forgesoc.ingestion.raw_jsonl import read_raw_records
from forgesoc.normalization.engine import NormalizationEngine
from forgesoc.normalization.linux_parser import LinuxAuditNormalizer, LinuxSshNormalizer
from forgesoc.normalization.models import (
    NormalizationError,
    NormalizationFailure,
    NormalizationReport,
    NormalizationSuccess,
)
from forgesoc.normalization.windows_parser import (
    WindowsAuthenticationNormalizer,
    WindowsSysmonNormalizer,
)
from forgesoc.output.events_jsonl import write_events
from forgesoc.output.rejections_jsonl import write_rejections


def build_engine() -> NormalizationEngine:
    return NormalizationEngine(
        [
            WindowsAuthenticationNormalizer(),
            WindowsSysmonNormalizer(),
            LinuxSshNormalizer(),
            LinuxAuditNormalizer(),
        ]
    )


def run_normalization(
    input_path: Path,
    output_path: Path,
    *,
    rejected_output_path: Path | None = None,
    continue_on_error: bool = False,
    overwrite: bool = False,
) -> NormalizationReport:
    if continue_on_error and rejected_output_path is None:
        raise ValueError("continue-on-error requires a rejected output path")

    output_paths = [output_path]
    if rejected_output_path is not None:
        output_paths.append(rejected_output_path)

    if len(set(output_paths)) != len(output_paths):
        raise ValueError("normalized and rejected output paths must be different")

    if not overwrite:
        existing = [path for path in output_paths if path.exists()]
        if existing:
            raise FileExistsError(f"Output already exists: {existing[0]}")

    engine = build_engine()
    results = list(
        engine.normalize(
            read_raw_records(input_path),
            continue_on_error=continue_on_error,
        )
    )
    successes = [
        result for result in results if isinstance(result, NormalizationSuccess)
    ]
    failures = [
        result for result in results if isinstance(result, NormalizationFailure)
    ]

    write_events(
        (result.event for result in successes),
        output_path,
        overwrite=overwrite,
    )
    if rejected_output_path is not None:
        write_rejections(
            failures,
            rejected_output_path,
            overwrite=overwrite,
        )

    return NormalizationReport.from_results(results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Normalize source telemetry into ForgeSOC security events."
    )
    parser.add_argument("input", type=Path, nargs="?")
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--rejected-output", type=Path)
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--list-sources", action="store_true")
    return parser


def _format_counts(values: Mapping[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in values.items()) or "none"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_sources:
        for source_type in build_engine().source_types:
            print(source_type)
        return

    if args.input is None or args.output is None:
        parser.error("input and output are required unless --list-sources is used")

    try:
        report = run_normalization(
            args.input,
            args.output,
            rejected_output_path=args.rejected_output,
            continue_on_error=args.continue_on_error,
            overwrite=args.force,
        )
    except (FileExistsError, NormalizationError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Records read: {report.records_read}")
    print(f"Events normalized: {report.events_normalized}")
    print(f"Events rejected: {report.events_rejected}")
    print(f"By source: {_format_counts(report.by_source)}")
    print(f"By event type: {_format_counts(report.by_event_type)}")
    print(f"By error: {_format_counts(report.by_error_code)}")


if __name__ == "__main__":
    main()
