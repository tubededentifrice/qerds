"""Base model definitions, mixins, and common types.

This module provides:
- SQLAlchemy declarative base with naming conventions
- Common mixins for timestamps and UUIDs
- Enum types used across multiple models
"""

import enum
import uuid
from datetime import datetime
from typing import Annotated

from sqlalchemy import DateTime, MetaData, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, mapped_column, registry

# Naming convention for constraints ensures consistent migration generation.
# See: https://alembic.sqlalchemy.org/en/latest/naming.html
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Shared metadata with naming convention
metadata = MetaData(naming_convention=NAMING_CONVENTION)

# Custom type registry for reusable type annotations
type_registry = registry()

# Common type annotations for columns
# UUID primary key with server-side default generation
UUIDPrimaryKey = Annotated[
    uuid.UUID,
    mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    ),
]

# UUID foreign key (not nullable by default)
UUIDForeignKey = Annotated[uuid.UUID, mapped_column(UUID(as_uuid=True))]

# Timestamp with timezone, defaults to now
TimestampTZ = Annotated[
    datetime,
    mapped_column(DateTime(timezone=True), server_default=text("now()")),
]

# Optional timestamp with timezone
OptionalTimestampTZ = Annotated[
    datetime | None,
    mapped_column(DateTime(timezone=True), nullable=True),
]

# Standard string lengths for common fields
ShortString = Annotated[str, mapped_column(String(100))]
MediumString = Annotated[str, mapped_column(String(255))]
LongString = Annotated[str, mapped_column(String(1000))]


class Base(DeclarativeBase):
    """Declarative base for all QERDS models.

    All models inherit from this base, which provides:
    - Consistent metadata with naming conventions
    - Type annotation support via mapped_column
    """

    metadata = metadata
    registry = type_registry


# =============================================================================
# Common Enums
# =============================================================================


class DeliveryState(enum.Enum):
    """Delivery lifecycle states per REQ-C01 state machine.

    States:
        DRAFT: Delivery created but not yet deposited
        DEPOSITED: Content deposited, ready for notification
        NOTIFIED: Recipient has been notified
        NOTIFICATION_FAILED: Notification delivery failed (requires retry/manual handling)
        AVAILABLE: Content available for recipient pickup
        ACCEPTED: Recipient explicitly accepted delivery
        REFUSED: Recipient explicitly refused delivery
        RECEIVED: Content successfully delivered/downloaded
        EXPIRED: Acceptance deadline passed without action
    """

    DRAFT = "draft"
    DEPOSITED = "deposited"
    NOTIFIED = "notified"
    NOTIFICATION_FAILED = "notification_failed"
    AVAILABLE = "available"
    ACCEPTED = "accepted"
    REFUSED = "refused"
    RECEIVED = "received"
    EXPIRED = "expired"


class PartyType(enum.Enum):
    """Type of party identity.

    Values:
        NATURAL_PERSON: Individual human being
        LEGAL_PERSON: Organization, company, or legal entity
    """

    NATURAL_PERSON = "natural_person"
    LEGAL_PERSON = "legal_person"


class IALLevel(enum.Enum):
    """Identity Assurance Level per eIDAS/NIST guidelines.

    Values:
        IAL1: Self-asserted identity (email verification)
        IAL2: Remote or in-person proofing (FranceConnect)
        IAL3: In-person proofing with biometric (FranceConnect+)
    """

    IAL1 = "ial1"
    IAL2 = "ial2"
    IAL3 = "ial3"


class ProofingMethod(enum.Enum):
    """Methods used to proof sender identity.

    Values:
        EMAIL_VERIFICATION: Simple email verification (IAL1)
        FRANCECONNECT: FranceConnect integration (IAL2)
        FRANCECONNECT_PLUS: FranceConnect+ with substantiel/high (IAL3)
        MANUAL_REVIEW: Manual document review by operator
    """

    EMAIL_VERIFICATION = "email_verification"
    FRANCECONNECT = "franceconnect"
    FRANCECONNECT_PLUS = "franceconnect_plus"
    MANUAL_REVIEW = "manual_review"


class ConsentType(enum.Enum):
    """Types of recipient consent per CPCE requirements (REQ-F06).

    Values:
        FR_LRE_ELECTRONIC_DELIVERY: French LRE electronic delivery consent
        EIDAS_ELECTRONIC_DELIVERY: eIDAS electronic delivery consent
    """

    FR_LRE_ELECTRONIC_DELIVERY = "fr_lre_electronic_delivery"
    EIDAS_ELECTRONIC_DELIVERY = "eidas_electronic_delivery"


class EncryptionScheme(enum.Enum):
    """Content encryption schemes.

    Values:
        AES_256_GCM: AES-256-GCM symmetric encryption
        NONE: No encryption (for non-confidential content)
    """

    AES_256_GCM = "aes_256_gcm"
    NONE = "none"


class EventType(enum.Enum):
    """Evidence event types for delivery lifecycle.

    Each event type corresponds to a specific point in the delivery
    process that must be recorded for compliance.
    """

    EVT_DEPOSITED = "evt_deposited"
    EVT_NOTIFICATION_SENT = "evt_notification_sent"
    EVT_NOTIFICATION_DELIVERED = "evt_notification_delivered"
    EVT_NOTIFICATION_FAILED = "evt_notification_failed"
    EVT_CONTENT_AVAILABLE = "evt_content_available"
    EVT_CONTENT_ACCESSED = "evt_content_accessed"
    EVT_CONTENT_DOWNLOADED = "evt_content_downloaded"
    EVT_ACCEPTED = "evt_accepted"
    EVT_REFUSED = "evt_refused"
    EVT_RECEIVED = "evt_received"
    EVT_EXPIRED = "evt_expired"
    EVT_RETENTION_EXTENDED = "evt_retention_extended"
    EVT_RETENTION_DELETED = "evt_retention_deleted"


class ActorType(enum.Enum):
    """Type of actor performing an action.

    Values:
        SENDER: The sending party
        RECIPIENT: The receiving party
        SYSTEM: Automated system action (e.g., expiry)
        ADMIN: Administrative user action
        API_CLIENT: External API client action
    """

    SENDER = "sender"
    RECIPIENT = "recipient"
    SYSTEM = "system"
    ADMIN = "admin"
    API_CLIENT = "api_client"


class QualificationLabel(enum.Enum):
    """Qualification status for evidence objects (REQ-G02).

    Values:
        QUALIFIED: Meets eIDAS/CPCE qualified requirements
        NON_QUALIFIED: Does not meet qualified requirements (dev/test)
    """

    QUALIFIED = "qualified"
    NON_QUALIFIED = "non_qualified"


class AuditStream(enum.Enum):
    """Audit log stream categories.

    Values:
        EVIDENCE: Delivery and evidence-related events
        SECURITY: Authentication, authorization, access events
        OPS: Operational events (config changes, maintenance)
    """

    EVIDENCE = "evidence"
    SECURITY = "security"
    OPS = "ops"


class RetentionActionType(enum.Enum):
    """Types of retention enforcement actions.

    Values:
        ARCHIVE: Move to long-term archive storage
        DELETE: Permanently delete after retention period
    """

    ARCHIVE = "archive"
    DELETE = "delete"


class JobStatus(enum.Enum):
    """Status of a background job.

    Values:
        PENDING: Job is waiting to be processed
        RUNNING: Job is currently being executed
        COMPLETED: Job finished successfully
        FAILED: Job failed after max retries
        CANCELLED: Job was manually cancelled
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
