"""SQLAlchemy ORM models for QERDS.

This package contains all database models organized by domain:
- base: Common metadata, mixins, and type definitions
- parties: Party identities, proofing, and consents
- deliveries: Delivery state machine and content objects
- evidence: Evidence events, objects, and policy snapshots
- auth: Admin users, API clients, roles, and bindings
- session: User session management
- audit: Audit log records and audit packs
- retention: Retention policies and actions
- jobs: PostgreSQL-backed job queue
"""

from qerds.db.models.audit import AuditLogRecord, AuditPack
from qerds.db.models.auth import AdminUser, ApiClient, Role, RoleBinding
from qerds.db.models.base import Base, metadata
from qerds.db.models.deliveries import ContentObject, Delivery
from qerds.db.models.evidence import EvidenceEvent, EvidenceObject, PolicySnapshot
from qerds.db.models.jobs import Job
from qerds.db.models.parties import Party, RecipientConsent, SenderProofing
from qerds.db.models.retention import RetentionAction, RetentionPolicy
from qerds.db.models.session import Session

__all__ = [
    "AdminUser",
    "ApiClient",
    "AuditLogRecord",
    "AuditPack",
    "Base",
    "ContentObject",
    "Delivery",
    "EvidenceEvent",
    "EvidenceObject",
    "Job",
    "Party",
    "PolicySnapshot",
    "RecipientConsent",
    "RetentionAction",
    "RetentionPolicy",
    "Role",
    "RoleBinding",
    "SenderProofing",
    "Session",
    "metadata",
]
