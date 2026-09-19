import argparse
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from forgesoc.detection.brute_force import BruteForceDetector
from forgesoc.ingestion.jsonl import read_events
from forgesoc.persistence.config import (
    DatabaseConfig,
    DatabaseConfigurationError,
)
from forgesoc.persistence.database import (
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from forgesoc.persistence.services import (
    DatabaseDetectionService,
    DatabaseStatsService,
    EventIngestionService,
)


def parse_timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must be ISO 8601") from exc

    if timestamp.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return timestamp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ForgeSOC PostgreSQL operations.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("health", help="Check database connectivity.")

    ingest = subparsers.add_parser("ingest", help="Persist canonical events.")
    ingest.add_argument("input", type=Path)

    detect = subparsers.add_parser("detect", help="Detect over a stored time range.")
    detect.add_argument("--start", type=parse_timestamp, required=True)
    detect.add_argument("--end", type=parse_timestamp, required=True)

    subparsers.add_parser("stats", help="Show persisted event and alert counts.")
    return parser


def _create_session_factory() -> SessionFactory:
    config = DatabaseConfig.from_environment()
    engine = create_database_engine(config)
    return create_session_factory(engine)


def _run_command(args: argparse.Namespace, session_factory: SessionFactory) -> None:
    if args.command == "health":
        with session_factory() as session:
            session.execute(text("SELECT 1"))
        print("Database connection is healthy.")
        return

    if args.command == "ingest":
        ingestion_summary = EventIngestionService(session_factory).ingest(
            read_events(args.input)
        )
        print(f"Events received: {ingestion_summary.events_received}")
        print(f"Events inserted: {ingestion_summary.events_inserted}")
        print(f"Duplicates: {ingestion_summary.duplicates}")
        return

    if args.command == "detect":
        service = DatabaseDetectionService(
            session_factory,
            detector_factory=lambda: [BruteForceDetector()],
        )
        detection_summary = service.detect(args.start, args.end)
        print(f"Events processed: {detection_summary.events_processed}")
        print(f"Alerts generated: {detection_summary.alerts_generated}")
        print(f"Alerts inserted: {detection_summary.alerts_inserted}")
        print(f"Duplicates: {detection_summary.duplicates}")
        return

    if args.command == "stats":
        stats = DatabaseStatsService(session_factory).get()
        print(f"Events: {stats.events}")
        print(f"Alerts: {stats.alerts}")
        print("Events by source:")
        if not stats.events_by_source:
            print("  none")
        for source, count in stats.events_by_source.items():
            print(f"  {source}: {count}")


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        _run_command(args, _create_session_factory())
    except DatabaseConfigurationError as exc:
        parser.error(str(exc))
    except SQLAlchemyError as exc:
        parser.error(f"database operation failed: {type(exc).__name__}")
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
