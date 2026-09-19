import json
from collections.abc import Iterable
from pathlib import Path

from forgesoc.domain.models import Alert


def write_alerts(alerts: Iterable[Alert], path: Path) -> int:
    alert_count = 0

    with path.open("w", encoding="utf-8") as file:
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

    return alert_count
