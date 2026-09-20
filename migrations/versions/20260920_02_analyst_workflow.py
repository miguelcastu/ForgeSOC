"""Add users, alert workflow, cases, notes, and audit trail.

Revision ID: 20260920_02
Revises: 20260919_01
Create Date: 2026-09-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260920_02"
down_revision: str | None = "20260919_01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "status", sa.String(length=32), server_default="open", nullable=False
        ),
    )
    op.add_column(
        "alerts",
        sa.Column("assignee_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "alerts", sa.Column("disposition", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "alerts",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_foreign_key(
        op.f("fk_alerts_assignee_user_id_users"),
        "alerts",
        "users",
        ["assignee_user_id"],
        ["user_id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_alerts_status_timestamp", "alerts", ["status", "timestamp"])

    op.create_table(
        "alert_notes",
        sa.Column("note_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("author_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.alert_id"],
            ondelete="CASCADE",
            name=op.f("fk_alert_notes_alert_id_alerts"),
        ),
        sa.ForeignKeyConstraint(
            ["author_user_id"],
            ["users.user_id"],
            ondelete="RESTRICT",
            name=op.f("fk_alert_notes_author_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("note_id", name=op.f("pk_alert_notes")),
    )

    op.create_table(
        "cases",
        sa.Column("case_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "status", sa.String(length=32), server_default="open", nullable=False
        ),
        sa.Column(
            "priority", sa.String(length=32), server_default="medium", nullable=False
        ),
        sa.Column("assignee_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["assignee_user_id"],
            ["users.user_id"],
            ondelete="SET NULL",
            name=op.f("fk_cases_assignee_user_id_users"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.user_id"],
            ondelete="RESTRICT",
            name=op.f("fk_cases_created_by_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_cases")),
    )
    op.create_table(
        "case_alerts",
        sa.Column("case_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.case_id"],
            ondelete="CASCADE",
            name=op.f("fk_case_alerts_case_id_cases"),
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.alert_id"],
            ondelete="CASCADE",
            name=op.f("fk_case_alerts_alert_id_alerts"),
        ),
        sa.PrimaryKeyConstraint("case_id", "alert_id", name=op.f("pk_case_alerts")),
    )
    op.create_table(
        "audit_log",
        sa.Column("audit_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.user_id"],
            ondelete="SET NULL",
            name=op.f("fk_audit_log_actor_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("audit_id", name=op.f("pk_audit_log")),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_timestamp", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("case_alerts")
    op.drop_table("cases")
    op.drop_table("alert_notes")
    op.drop_index("ix_alerts_status_timestamp", table_name="alerts")
    op.drop_constraint(
        op.f("fk_alerts_assignee_user_id_users"), "alerts", type_="foreignkey"
    )
    op.drop_column("alerts", "updated_at")
    op.drop_column("alerts", "disposition")
    op.drop_column("alerts", "assignee_user_id")
    op.drop_column("alerts", "status")
    op.drop_table("users")
