"""Add sessions table for user session management.

Revision ID: 002
Revises: 001
Create Date: 2026-01-22 12:19:00.000000+00:00

Creates the sessions table for:
- Session token storage (hashed)
- Multi-device session tracking
- Session expiration and revocation
- Activity tracking
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration: Add sessions table."""
    op.create_table(
        "sessions",
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # Token hash (SHA-256 of the actual token)
        sa.Column("token_hash", sa.String(64), nullable=False),
        # Principal linkage (one of these must be set - enforced at application level)
        sa.Column("admin_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("api_client_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("party_id", postgresql.UUID(as_uuid=True), nullable=True),
        # Session type for quick filtering
        sa.Column("session_type", sa.String(50), nullable=False, server_default="user"),
        # Session validity
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        # Activity tracking
        sa.Column(
            "last_activity_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("activity_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        # Device/client information
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("device_id", sa.String(255), nullable=True),
        # Geographic info (from IP geolocation)
        sa.Column("geo_country", sa.String(2), nullable=True),
        sa.Column("geo_city", sa.String(100), nullable=True),
        # Refresh token support
        sa.Column("refresh_token_hash", sa.String(64), nullable=True),
        sa.Column("refresh_expires_at", sa.DateTime(timezone=True), nullable=True),
        # Revocation tracking
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revocation_reason", sa.String(255), nullable=True),
        # Additional metadata
        sa.Column("session_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # Primary key
        sa.PrimaryKeyConstraint("session_id", name=op.f("pk_sessions")),
        # Unique constraint on token hash
        sa.UniqueConstraint("token_hash", name=op.f("uq_sessions_token_hash")),
        # Foreign key constraints
        sa.ForeignKeyConstraint(
            ["admin_user_id"],
            ["admin_users.admin_user_id"],
            name=op.f("fk_sessions_admin_user_id_admin_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["api_client_id"],
            ["api_clients.api_client_id"],
            name=op.f("fk_sessions_api_client_id_api_clients"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["party_id"],
            ["parties.party_id"],
            name=op.f("fk_sessions_party_id_parties"),
            ondelete="CASCADE",
        ),
    )

    # Create indexes
    op.create_index(op.f("ix_sessions_token_hash"), "sessions", ["token_hash"], unique=True)
    op.create_index(op.f("ix_sessions_admin_user_id"), "sessions", ["admin_user_id"], unique=False)
    op.create_index(op.f("ix_sessions_api_client_id"), "sessions", ["api_client_id"], unique=False)
    op.create_index(op.f("ix_sessions_party_id"), "sessions", ["party_id"], unique=False)
    op.create_index(op.f("ix_sessions_expires_at"), "sessions", ["expires_at"], unique=False)
    op.create_index(op.f("ix_sessions_is_active"), "sessions", ["is_active"], unique=False)

    # Partial index for active admin user sessions
    op.create_index(
        op.f("ix_sessions_admin_user_active"),
        "sessions",
        ["admin_user_id", "is_active"],
        unique=False,
        postgresql_where=sa.text("is_active = true"),
    )


def downgrade() -> None:
    """Revert migration: Remove sessions table."""
    op.drop_index(op.f("ix_sessions_admin_user_active"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_is_active"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_expires_at"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_party_id"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_api_client_id"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_admin_user_id"), table_name="sessions")
    op.drop_index(op.f("ix_sessions_token_hash"), table_name="sessions")
    op.drop_table("sessions")
