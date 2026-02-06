"""initial schema

Revision ID: a559bd8b46c8
Revises:
Create Date: 2026-02-07 01:56:37.153279

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'a559bd8b46c8'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- organizations ---
    op.create_table(
        "organizations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False, unique=True),
        sa.Column("plan", sa.String(), nullable=False, server_default="free"),
        sa.Column("trace_limit_monthly", sa.Integer(), nullable=False, server_default="10000"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # --- api_keys ---
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default="default"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])

    # --- agents ---
    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id_external", sa.String(), nullable=False),
        sa.Column("agent_type", sa.String(), nullable=True),
        sa.Column("declared_intent", sa.String(), nullable=True),
        sa.Column("framework", sa.String(), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "agent_id_external", name="uq_agents_org_external"),
    )

    # --- traces ---
    op.create_table(
        "traces",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("task_id", sa.String(), nullable=True),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("declared_intent", sa.String(), nullable=True),
        sa.Column("action_count", sa.Integer(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False, server_default="safe"),
        sa.Column("actions", postgresql.JSONB(), nullable=False),
        sa.Column("semantic_flags", postgresql.JSONB(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("environment", sa.String(), nullable=True, server_default="production"),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_traces_org_id", "traces", ["org_id"])

    # --- detection_rules ---
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("rule_id_human", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("rule_type", sa.String(), nullable=False),
        sa.Column("rule_content", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_system_rule", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # --- alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("trace_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("rule_id", sa.Uuid(), sa.ForeignKey("detection_rules.id"), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("context", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_alerts_org_id", "alerts", ["org_id"])

    # --- notification_channels ---
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("channel_type", sa.String(), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # --- audit_log ---
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("previous_value", postgresql.JSONB(), nullable=True),
        sa.Column("new_value", postgresql.JSONB(), nullable=True),
        sa.Column("changed_by", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # --- org_configs ---
    op.create_table(
        "org_configs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("default_mode", sa.String(), nullable=False, server_default="safe"),
        sa.Column("trace_retention_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_by", sa.Text(), nullable=True),
    )

    # --- usage_meters ---
    op.create_table(
        "usage_meters",
        sa.Column("org_id", sa.Uuid(), sa.ForeignKey("organizations.id"), primary_key=True),
        sa.Column("period_start", sa.Date(), primary_key=True),
        sa.Column("trace_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alert_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("usage_meters")
    op.drop_table("org_configs")
    op.drop_table("audit_log")
    op.drop_table("notification_channels")
    op.drop_index("ix_alerts_org_id", table_name="alerts")
    op.drop_table("alerts")
    op.drop_table("detection_rules")
    op.drop_index("ix_traces_org_id", table_name="traces")
    op.drop_table("traces")
    op.drop_table("agents")
    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_table("organizations")
