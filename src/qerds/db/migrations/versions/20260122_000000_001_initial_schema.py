"""Initial schema with all core tables.

Revision ID: 001
Revises: None
Create Date: 2026-01-22 00:00:00.000000+00:00

Creates all tables for QERDS:
- parties, sender_proofing, recipient_consents (identity)
- deliveries, content_objects (delivery state machine)
- evidence_events, evidence_objects, policy_snapshots (evidence)
- admin_users, api_clients, roles, role_bindings (auth/RBAC)
- audit_log_records, audit_packs (audit)
- retention_policies, retention_actions (retention)
- jobs (background processing)
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration: Initial schema with all core tables."""
    # Create enum types first
    party_type = postgresql.ENUM(
        "natural_person", "legal_person", name="party_type", create_type=False
    )
    party_type.create(op.get_bind(), checkfirst=True)

    ial_level = postgresql.ENUM("ial1", "ial2", "ial3", name="ial_level", create_type=False)
    ial_level.create(op.get_bind(), checkfirst=True)

    proofing_method = postgresql.ENUM(
        "email_verification",
        "franceconnect",
        "franceconnect_plus",
        "manual_review",
        name="proofing_method",
        create_type=False,
    )
    proofing_method.create(op.get_bind(), checkfirst=True)

    consent_type = postgresql.ENUM(
        "fr_lre_electronic_delivery",
        "eidas_electronic_delivery",
        name="consent_type",
        create_type=False,
    )
    consent_type.create(op.get_bind(), checkfirst=True)

    delivery_state = postgresql.ENUM(
        "draft",
        "deposited",
        "notified",
        "available",
        "accepted",
        "refused",
        "received",
        "expired",
        name="delivery_state",
        create_type=False,
    )
    delivery_state.create(op.get_bind(), checkfirst=True)

    encryption_scheme = postgresql.ENUM(
        "aes_256_gcm", "none", name="encryption_scheme", create_type=False
    )
    encryption_scheme.create(op.get_bind(), checkfirst=True)

    event_type = postgresql.ENUM(
        "evt_deposited",
        "evt_notification_sent",
        "evt_notification_delivered",
        "evt_notification_failed",
        "evt_content_available",
        "evt_content_accessed",
        "evt_content_downloaded",
        "evt_accepted",
        "evt_refused",
        "evt_expired",
        "evt_retention_extended",
        "evt_retention_deleted",
        name="event_type",
        create_type=False,
    )
    event_type.create(op.get_bind(), checkfirst=True)

    actor_type = postgresql.ENUM(
        "sender", "recipient", "system", "admin", "api_client", name="actor_type", create_type=False
    )
    actor_type.create(op.get_bind(), checkfirst=True)

    qualification_label = postgresql.ENUM(
        "qualified", "non_qualified", name="qualification_label", create_type=False
    )
    qualification_label.create(op.get_bind(), checkfirst=True)

    audit_stream = postgresql.ENUM(
        "evidence", "security", "ops", name="audit_stream", create_type=False
    )
    audit_stream.create(op.get_bind(), checkfirst=True)

    retention_action_type = postgresql.ENUM(
        "archive", "delete", name="retention_action_type", create_type=False
    )
    retention_action_type.create(op.get_bind(), checkfirst=True)

    job_status = postgresql.ENUM(
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
        name="job_status",
        create_type=False,
    )
    job_status.create(op.get_bind(), checkfirst=True)

    # =========================================================================
    # Parties domain
    # =========================================================================
    op.create_table(
        "parties",
        sa.Column(
            "party_id",
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
        sa.Column("party_type", party_type, nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("identity_data", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("redaction_profile", sa.String(100), nullable=True),
        sa.Column("external_id", sa.String(255), nullable=True),
        sa.Column("external_provider", sa.String(100), nullable=True),
        sa.PrimaryKeyConstraint("party_id", name=op.f("pk_parties")),
    )
    op.create_index(op.f("ix_parties_email"), "parties", ["email"], unique=False)
    op.create_index(
        op.f("ix_parties_external_id"),
        "parties",
        ["external_provider", "external_id"],
        unique=False,
    )

    op.create_table(
        "sender_proofing",
        sa.Column(
            "proofing_id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("party_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ial_level", ial_level, nullable=False),
        sa.Column("proofing_method", proofing_method, nullable=False),
        sa.Column("proofing_evidence_object_ref", sa.String(500), nullable=True),
        sa.Column(
            "proofed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("proofing_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["party_id"],
            ["parties.party_id"],
            name=op.f("fk_sender_proofing_party_id_parties"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("proofing_id", name=op.f("pk_sender_proofing")),
    )
    op.create_index(
        op.f("ix_sender_proofing_party_id"), "sender_proofing", ["party_id"], unique=False
    )
    op.create_index(
        op.f("ix_sender_proofing_proofed_at"), "sender_proofing", ["proofed_at"], unique=False
    )

    op.create_table(
        "recipient_consents",
        sa.Column(
            "consent_id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("recipient_party_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("consent_type", consent_type, nullable=False),
        sa.Column("consented_at", sa.DateTime(), nullable=False),
        sa.Column("consented_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("consent_evidence_object_ref", sa.String(500), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("consent_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["recipient_party_id"],
            ["parties.party_id"],
            name=op.f("fk_recipient_consents_recipient_party_id_parties"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("consent_id", name=op.f("pk_recipient_consents")),
    )
    op.create_index(
        op.f("ix_recipient_consents_party_id"),
        "recipient_consents",
        ["recipient_party_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_recipient_consents_type"), "recipient_consents", ["consent_type"], unique=False
    )

    # =========================================================================
    # Policy snapshots (needed before evidence_events for FK)
    # =========================================================================
    op.create_table(
        "policy_snapshots",
        sa.Column(
            "policy_snapshot_id",
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
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("doc_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("config_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("snapshot_hash", sa.String(64), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.PrimaryKeyConstraint("policy_snapshot_id", name=op.f("pk_policy_snapshots")),
    )
    op.create_index(
        op.f("ix_policy_snapshots_created_at"), "policy_snapshots", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_policy_snapshots_is_active"), "policy_snapshots", ["is_active"], unique=False
    )

    # =========================================================================
    # Deliveries domain
    # =========================================================================
    op.create_table(
        "deliveries",
        sa.Column(
            "delivery_id",
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
        sa.Column("state", delivery_state, nullable=False, server_default=sa.text("'draft'")),
        sa.Column("sender_party_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("recipient_party_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("jurisdiction_profile", sa.String(50), nullable=False, server_default="eidas"),
        sa.Column("acceptance_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pre_acceptance_redaction_profile", sa.String(100), nullable=True),
        sa.Column("subject", sa.String(500), nullable=True),
        sa.Column("message", sa.String(10000), nullable=True),
        sa.Column("delivery_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("deposited_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["sender_party_id"],
            ["parties.party_id"],
            name=op.f("fk_deliveries_sender_party_id_parties"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_party_id"],
            ["parties.party_id"],
            name=op.f("fk_deliveries_recipient_party_id_parties"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("delivery_id", name=op.f("pk_deliveries")),
    )
    op.create_index(
        op.f("ix_deliveries_sender_party_id"), "deliveries", ["sender_party_id"], unique=False
    )
    op.create_index(
        op.f("ix_deliveries_recipient_party_id"), "deliveries", ["recipient_party_id"], unique=False
    )
    op.create_index(op.f("ix_deliveries_state"), "deliveries", ["state"], unique=False)
    op.create_index(op.f("ix_deliveries_created_at"), "deliveries", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_deliveries_acceptance_deadline"),
        "deliveries",
        ["acceptance_deadline_at"],
        unique=False,
    )

    op.create_table(
        "content_objects",
        sa.Column(
            "content_object_id",
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
        sa.Column("delivery_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.String(255), nullable=False),
        sa.Column("original_filename", sa.String(500), nullable=True),
        sa.Column("storage_key", sa.String(500), nullable=False),
        sa.Column(
            "encryption_scheme",
            encryption_scheme,
            nullable=False,
            server_default=sa.text("'aes_256_gcm'"),
        ),
        sa.Column("encryption_metadata_ref", sa.String(500), nullable=True),
        sa.Column("content_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["delivery_id"],
            ["deliveries.delivery_id"],
            name=op.f("fk_content_objects_delivery_id_deliveries"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("content_object_id", name=op.f("pk_content_objects")),
    )
    op.create_index(
        op.f("ix_content_objects_delivery_id"), "content_objects", ["delivery_id"], unique=False
    )
    op.create_index(op.f("ix_content_objects_sha256"), "content_objects", ["sha256"], unique=False)

    # =========================================================================
    # Evidence domain
    # =========================================================================
    op.create_table(
        "evidence_events",
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("delivery_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", event_type, nullable=False),
        sa.Column(
            "event_time",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("actor_type", actor_type, nullable=False),
        sa.Column("actor_ref", sa.String(255), nullable=False),
        sa.Column("policy_snapshot_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["delivery_id"],
            ["deliveries.delivery_id"],
            name=op.f("fk_evidence_events_delivery_id_deliveries"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["policy_snapshot_id"],
            ["policy_snapshots.policy_snapshot_id"],
            name=op.f("fk_evidence_events_policy_snapshot_id_policy_snapshots"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_evidence_events")),
    )
    op.create_index(
        op.f("ix_evidence_events_delivery_id"), "evidence_events", ["delivery_id"], unique=False
    )
    op.create_index(
        op.f("ix_evidence_events_event_type"), "evidence_events", ["event_type"], unique=False
    )
    op.create_index(
        op.f("ix_evidence_events_event_time"), "evidence_events", ["event_time"], unique=False
    )
    op.create_index(
        op.f("ix_evidence_events_actor_type"), "evidence_events", ["actor_type"], unique=False
    )

    op.create_table(
        "evidence_objects",
        sa.Column(
            "evidence_object_id",
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
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_payload_digest", sa.String(64), nullable=False),
        sa.Column("provider_attestation_blob_ref", sa.String(500), nullable=True),
        sa.Column("time_attestation_blob_ref", sa.String(500), nullable=True),
        sa.Column("verification_bundle_blob_ref", sa.String(500), nullable=True),
        sa.Column(
            "qualification_label",
            qualification_label,
            nullable=False,
            server_default=sa.text("'non_qualified'"),
        ),
        sa.Column("qualification_reason", sa.Text(), nullable=True),
        sa.Column("evidence_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["evidence_events.event_id"],
            name=op.f("fk_evidence_objects_event_id_evidence_events"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("evidence_object_id", name=op.f("pk_evidence_objects")),
    )
    op.create_index(
        op.f("ix_evidence_objects_event_id"), "evidence_objects", ["event_id"], unique=False
    )
    op.create_index(
        op.f("ix_evidence_objects_qualification_label"),
        "evidence_objects",
        ["qualification_label"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_objects_created_at"), "evidence_objects", ["created_at"], unique=False
    )

    # =========================================================================
    # Auth/RBAC domain
    # =========================================================================
    op.create_table(
        "admin_users",
        sa.Column(
            "admin_user_id",
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
        sa.Column("username", sa.String(100), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("external_id", sa.String(255), nullable=True),
        sa.Column("external_provider", sa.String(100), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("mfa_secret_ref", sa.String(500), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("admin_user_id", name=op.f("pk_admin_users")),
        sa.UniqueConstraint("username", name=op.f("uq_admin_users_username")),
        sa.UniqueConstraint("email", name=op.f("uq_admin_users_email")),
    )
    op.create_index(
        op.f("ix_admin_users_external_id"),
        "admin_users",
        ["external_provider", "external_id"],
        unique=False,
    )

    op.create_table(
        "api_clients",
        sa.Column(
            "api_client_id",
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
        sa.Column("client_id", sa.String(100), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("client_secret_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("allowed_scopes", postgresql.ARRAY(sa.String(100)), nullable=True),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=True),
        sa.Column("allowed_ips", postgresql.ARRAY(sa.String(50)), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("client_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["admin_users.admin_user_id"],
            name=op.f("fk_api_clients_created_by_admin_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("api_client_id", name=op.f("pk_api_clients")),
        sa.UniqueConstraint("client_id", name=op.f("uq_api_clients_client_id")),
    )
    op.create_index(op.f("ix_api_clients_client_id"), "api_clients", ["client_id"], unique=False)

    op.create_table(
        "roles",
        sa.Column(
            "role_id",
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
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "permissions",
            postgresql.ARRAY(sa.String(100)),
            nullable=False,
            server_default=sa.text("'{}'::character varying[]"),
        ),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("parent_role_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_role_id"],
            ["roles.role_id"],
            name=op.f("fk_roles_parent_role_id_roles"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("role_id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name=op.f("uq_roles_name")),
    )
    op.create_index(op.f("ix_roles_name"), "roles", ["name"], unique=False)

    op.create_table(
        "role_bindings",
        sa.Column(
            "binding_id",
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
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("admin_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("api_client_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scope_filter", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("granted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.role_id"],
            name=op.f("fk_role_bindings_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["admin_user_id"],
            ["admin_users.admin_user_id"],
            name=op.f("fk_role_bindings_admin_user_id_admin_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["api_client_id"],
            ["api_clients.api_client_id"],
            name=op.f("fk_role_bindings_api_client_id_api_clients"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("binding_id", name=op.f("pk_role_bindings")),
        sa.UniqueConstraint("role_id", "admin_user_id", name="uq_role_bindings_role_admin_user"),
        sa.UniqueConstraint("role_id", "api_client_id", name="uq_role_bindings_role_api_client"),
    )
    op.create_index(op.f("ix_role_bindings_role_id"), "role_bindings", ["role_id"], unique=False)
    op.create_index(
        op.f("ix_role_bindings_admin_user_id"), "role_bindings", ["admin_user_id"], unique=False
    )
    op.create_index(
        op.f("ix_role_bindings_api_client_id"), "role_bindings", ["api_client_id"], unique=False
    )

    # =========================================================================
    # Audit domain
    # =========================================================================
    op.create_table(
        "audit_log_records",
        sa.Column(
            "record_id",
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
        sa.Column("stream", audit_stream, nullable=False),
        sa.Column("seq_no", sa.BigInteger(), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("prev_record_hash", sa.String(64), nullable=True),
        sa.Column("payload_ref", sa.String(500), nullable=False),
        sa.Column("sealed_checkpoint_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("actor_type", sa.String(50), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("record_id", name=op.f("pk_audit_log_records")),
    )
    op.create_index(
        op.f("ix_audit_log_records_stream"),
        "audit_log_records",
        ["stream"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_log_records_stream_seq"),
        "audit_log_records",
        ["stream", "seq_no"],
        unique=True,
    )
    op.create_index(
        op.f("ix_audit_log_records_created_at"),
        "audit_log_records",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_log_records_event_type"),
        "audit_log_records",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_log_records_actor"),
        "audit_log_records",
        ["actor_type", "actor_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_log_records_resource"),
        "audit_log_records",
        ["resource_type", "resource_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_log_records_checkpoint"),
        "audit_log_records",
        ["sealed_checkpoint_id"],
        unique=False,
    )

    op.create_table(
        "audit_packs",
        sa.Column(
            "audit_pack_id",
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
            "range_start",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "range_end",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("streams", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("generated_by", sa.String(255), nullable=False),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("object_store_ref", sa.String(500), nullable=False),
        sa.Column("sealed_evidence_object_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("pack_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_by", sa.String(255), nullable=True),
        sa.ForeignKeyConstraint(
            ["sealed_evidence_object_id"],
            ["evidence_objects.evidence_object_id"],
            name=op.f("fk_audit_packs_sealed_evidence_object_id_evidence_objects"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("audit_pack_id", name=op.f("pk_audit_packs")),
    )
    op.create_index(
        op.f("ix_audit_packs_range"), "audit_packs", ["range_start", "range_end"], unique=False
    )
    op.create_index(
        op.f("ix_audit_packs_generated_at"), "audit_packs", ["generated_at"], unique=False
    )

    # =========================================================================
    # Retention domain
    # =========================================================================
    op.create_table(
        "retention_policies",
        sa.Column(
            "policy_id",
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
        sa.Column("artifact_type", sa.String(100), nullable=False),
        sa.Column("policy_version", sa.String(50), nullable=False),
        sa.Column("minimum_retention_days", sa.Integer(), nullable=False),
        sa.Column("maximum_retention_days", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("jurisdiction_profile", sa.String(50), nullable=True),
        sa.Column(
            "expiry_action",
            retention_action_type,
            nullable=False,
            server_default=sa.text("'archive'"),
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("policy_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("policy_id", name=op.f("pk_retention_policies")),
    )
    op.create_index(
        op.f("ix_retention_policies_artifact_type"),
        "retention_policies",
        ["artifact_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_retention_policies_is_active"), "retention_policies", ["is_active"], unique=False
    )
    op.create_index(
        op.f("ix_retention_policies_type_jurisdiction"),
        "retention_policies",
        ["artifact_type", "jurisdiction_profile"],
        unique=False,
    )

    op.create_table(
        "retention_actions",
        sa.Column(
            "action_id",
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
        sa.Column("artifact_type", sa.String(100), nullable=False),
        sa.Column("artifact_ref", sa.String(500), nullable=False),
        sa.Column("action_type", retention_action_type, nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(), nullable=False),
        sa.Column("executed_by", sa.String(255), nullable=False),
        sa.Column("result", sa.String(50), nullable=False),
        sa.Column("result_message", sa.Text(), nullable=True),
        sa.Column("audit_log_record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("archive_ref", sa.String(500), nullable=True),
        sa.Column("artifact_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("artifact_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("retention_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["retention_policies.policy_id"],
            name=op.f("fk_retention_actions_policy_id_retention_policies"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["audit_log_record_id"],
            ["audit_log_records.record_id"],
            name=op.f("fk_retention_actions_audit_log_record_id_audit_log_records"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("action_id", name=op.f("pk_retention_actions")),
    )
    op.create_index(
        op.f("ix_retention_actions_artifact_type"),
        "retention_actions",
        ["artifact_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_retention_actions_executed_at"), "retention_actions", ["executed_at"], unique=False
    )
    op.create_index(
        op.f("ix_retention_actions_result"), "retention_actions", ["result"], unique=False
    )
    op.create_index(
        op.f("ix_retention_actions_policy_id"), "retention_actions", ["policy_id"], unique=False
    )

    # =========================================================================
    # Jobs domain
    # =========================================================================
    op.create_table(
        "jobs",
        sa.Column(
            "job_id",
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
        sa.Column("job_type", sa.String(100), nullable=False),
        sa.Column("status", job_status, nullable=False, server_default=sa.text("'pending'")),
        sa.Column("run_at", sa.DateTime(), nullable=False),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(255), nullable=True),
        sa.Column(
            "lock_timeout_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("300"),
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default=sa.text("3")),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "base_backoff_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("result_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("100")),
        sa.Column("queue", sa.String(100), nullable=False, server_default="default"),
        sa.Column("correlation_id", sa.String(255), nullable=True),
        sa.Column("parent_job_id", sa.String(255), nullable=True),
        sa.Column("estimated_duration_seconds", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_jobs")),
    )
    op.create_index(
        op.f("ix_jobs_queue_pending"),
        "jobs",
        ["queue", "status", "run_at", "priority"],
        unique=False,
    )
    op.create_index(op.f("ix_jobs_status"), "jobs", ["status"], unique=False)
    op.create_index(op.f("ix_jobs_job_type"), "jobs", ["job_type"], unique=False)
    op.create_index(op.f("ix_jobs_run_at"), "jobs", ["run_at"], unique=False)
    op.create_index(op.f("ix_jobs_correlation_id"), "jobs", ["correlation_id"], unique=False)
    op.create_index(op.f("ix_jobs_completed_at"), "jobs", ["completed_at"], unique=False)


def downgrade() -> None:
    """Revert migration: Initial schema with all core tables."""
    # Drop tables in reverse order (respecting foreign key dependencies)
    op.drop_table("jobs")
    op.drop_table("retention_actions")
    op.drop_table("retention_policies")
    op.drop_table("audit_packs")
    op.drop_table("audit_log_records")
    op.drop_table("role_bindings")
    op.drop_table("roles")
    op.drop_table("api_clients")
    op.drop_table("admin_users")
    op.drop_table("evidence_objects")
    op.drop_table("evidence_events")
    op.drop_table("content_objects")
    op.drop_table("deliveries")
    op.drop_table("policy_snapshots")
    op.drop_table("recipient_consents")
    op.drop_table("sender_proofing")
    op.drop_table("parties")

    # Drop enum types
    op.execute("DROP TYPE IF EXISTS job_status")
    op.execute("DROP TYPE IF EXISTS retention_action_type")
    op.execute("DROP TYPE IF EXISTS audit_stream")
    op.execute("DROP TYPE IF EXISTS qualification_label")
    op.execute("DROP TYPE IF EXISTS actor_type")
    op.execute("DROP TYPE IF EXISTS event_type")
    op.execute("DROP TYPE IF EXISTS encryption_scheme")
    op.execute("DROP TYPE IF EXISTS delivery_state")
    op.execute("DROP TYPE IF EXISTS consent_type")
    op.execute("DROP TYPE IF EXISTS proofing_method")
    op.execute("DROP TYPE IF EXISTS ial_level")
    op.execute("DROP TYPE IF EXISTS party_type")
