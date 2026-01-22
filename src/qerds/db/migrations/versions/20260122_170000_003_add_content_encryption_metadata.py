"""Add encryption metadata JSONB column to content_objects.

Revision ID: 003
Revises: 002
Create Date: 2026-01-22 17:00:00.000000+00:00

Adds encryption_metadata JSONB column to store envelope encryption details:
- wrapped_dek: Base64-encoded DEK encrypted with KEK
- kek_id: ID of the KEK used to wrap the DEK
- nonce: GCM nonce for content decryption
- algorithm: Encryption algorithm identifier
- encrypted_at: When encryption was performed

This supports REQ-E01 (content encryption at rest) and REQ-E02 (content access gating).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply migration: Add encryption_metadata JSONB column."""
    # Add encryption_metadata JSONB column to content_objects
    # This stores the full envelope encryption metadata:
    # {
    #   "version": "1.0",
    #   "algorithm": "aes_256_gcm",
    #   "nonce": "base64...",
    #   "wrapped_dek": "base64...",
    #   "kek_id": "kek-uuid...",
    #   "content_hash": "sha256...",
    #   "encrypted_at": "iso8601..."
    # }
    op.add_column(
        "content_objects",
        sa.Column(
            "encryption_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )

    # Add index on encryption_metadata for querying by kek_id (for key rotation)
    # Using a GIN index for JSONB
    op.create_index(
        op.f("ix_content_objects_encryption_kek"),
        "content_objects",
        [sa.text("(encryption_metadata->>'kek_id')")],
        unique=False,
    )


def downgrade() -> None:
    """Revert migration: Remove encryption_metadata column."""
    op.drop_index(op.f("ix_content_objects_encryption_kek"), table_name="content_objects")
    op.drop_column("content_objects", "encryption_metadata")
