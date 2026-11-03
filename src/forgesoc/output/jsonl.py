import json
import os
from collections.abc import Iterable
from pathlib import Path
from tempfile import NamedTemporaryFile

from forgesoc.domain.models import Alert


def write_alerts(alerts: Iterable[Alert], path: Path) -> int:
    alert_count = 0

    # Keep the prior complete output until lazy ingestion and detection succeed.
    # A sibling file permits same-filesystem atomic replacement on Windows too.
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            for alert in alerts:
                record = {
                    "alert_id": alert.alert_id,
                    "timestamp": alert.timestamp.isoformat(),
                    "rule_id": alert.rule_id,
                    "title": alert.title,
                    "severity": alert.severity.value,
                    "username": alert.username,
                    "source_ip": alert.source_ip,
                    "related_event_ids": list(alert.related_event_ids),
                    "reason": alert.reason,
                }
                file.write(json.dumps(record, ensure_ascii=False))
                file.write("\n")
                alert_count += 1
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return alert_count
