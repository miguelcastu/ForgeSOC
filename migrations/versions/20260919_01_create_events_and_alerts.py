"""Create events, alerts, and alert evidence tables.

Revision ID: 20260919_01
Revises:
Create Date: 2026-09-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260919_01"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_record_id", sa.String(length=255), nullable=True),
        sa.Column("username", sa.Text(), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=True),
        sa.Column("host", sa.Text(), nullable=True),
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_events")),
        sa.UniqueConstraint(
            "source",
            "source_record_id",
            name=op.f("uq_events_source_source_record_id"),
        ),
    )
    op.create_index(
        "ix_events_timestamp_event_id",
        "events",
        ["timestamp", "event_id"],
    )
    op.create_index(
        "ix_events_event_type_timestamp",
        "events",
        ["event_type", "timestamp"],
    )
    op.create_index(
        "ix_events_username_timestamp",
        "events",
        ["username", "timestamp"],
    )
    op.create_index(
        "ix_events_source_ip_timestamp",
        "events",
        ["source_ip", "timestamp"],
    )

    op.create_table(
        "alerts",
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("username", sa.Text(), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("alert_id", name=op.f("pk_alerts")),
    )
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])
    op.create_index(
        "ix_alerts_rule_id_timestamp",
        "alerts",
        ["rule_id", "timestamp"],
    )
    op.create_index(
        "ix_alerts_severity_timestamp",
        "alerts",
        ["severity", "timestamp"],
    )

    op.create_table(
        "alert_events",
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_order", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.alert_id"],
            name=op.f("fk_alert_events_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.event_id"],
            name=op.f("fk_alert_events_event_id_events"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "alert_id",
            "event_id",
            name=op.f("pk_alert_events"),
        ),
        sa.UniqueConstraint(
            "alert_id",
            "evidence_order",
            name=op.f("uq_alert_events_alert_id_evidence_order"),
        ),
    )


def downgrade() -> None:
    op.drop_table("alert_events")
    op.drop_index("ix_alerts_severity_timestamp", table_name="alerts")
    op.drop_index("ix_alerts_rule_id_timestamp", table_name="alerts")
    op.drop_index("ix_alerts_timestamp", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_events_source_ip_timestamp", table_name="events")
    op.drop_index("ix_events_username_timestamp", table_name="events")
    op.drop_index("ix_events_event_type_timestamp", table_name="events")
    op.drop_index("ix_events_timestamp_event_id", table_name="events")
    op.drop_table("events")
