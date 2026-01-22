"""Pydantic schemas for admin API endpoints.

Covers: REQ-D02 (access control), REQ-D08 (logging), REQ-H01 (audit packs),
        REQ-H04 (incident response), REQ-H05 (config snapshots), REQ-H06 (access review),
        REQ-H10 (dispute reconstruction)

These schemas define the request/response models for administrative operations
including audit pack generation, config snapshots, access reviews, and incident management.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# -----------------------------------------------------------------------------
# Audit Pack Schemas (REQ-H01)
# -----------------------------------------------------------------------------


class AuditPackRequest(BaseModel):
    """Request schema for generating an audit pack.

    Audit packs are comprehensive exports of evidence and audit data
    for a specified date range, used for regulatory review or audits.
    """

    start_date: date = Field(..., description="Start date for audit pack (inclusive)")
    end_date: date = Field(..., description="End date for audit pack (inclusive)")
    include_evidence: bool = Field(True, description="Include evidence events and objects")
    include_security_logs: bool = Field(True, description="Include security audit logs")
    include_ops_logs: bool = Field(False, description="Include operational audit logs")
    include_config_snapshots: bool = Field(True, description="Include config snapshots in range")
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Reason for generating the audit pack (for audit trail)",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("end_date")
    @classmethod
    def validate_date_range(cls, v: date, info: Any) -> date:
        """Ensure end_date is not before start_date."""
        start = info.data.get("start_date")
        if start and v < start:
            msg = "end_date must not be before start_date"
            raise ValueError(msg)
        return v


class AuditPackResponse(BaseModel):
    """Response schema for audit pack generation."""

    pack_id: UUID = Field(..., description="Unique identifier for the audit pack")
    start_date: date = Field(..., description="Start date of the pack")
    end_date: date = Field(..., description="End date of the pack")
    created_at: datetime = Field(..., description="When the pack was generated")
    created_by: str = Field(..., description="Admin user who created the pack")
    evidence_count: int = Field(0, description="Number of evidence events included")
    security_log_count: int = Field(0, description="Number of security log entries")
    ops_log_count: int = Field(0, description="Number of ops log entries")
    config_snapshot_count: int = Field(0, description="Number of config snapshots")
    pack_hash: str = Field(..., description="SHA-256 hash of the pack contents")
    storage_ref: str = Field(..., description="Reference to stored audit pack")
    verification: AuditPackVerification = Field(..., description="Chain verification results")


class AuditPackVerification(BaseModel):
    """Verification results for audit pack integrity."""

    evidence_chain_valid: bool = Field(..., description="Evidence audit chain integrity")
    security_chain_valid: bool = Field(..., description="Security audit chain integrity")
    ops_chain_valid: bool = Field(..., description="Ops audit chain integrity")
    errors: list[str] = Field(default_factory=list, description="Any verification errors")


# -----------------------------------------------------------------------------
# Timeline/Dispute Reconstruction Schemas (REQ-H10)
# -----------------------------------------------------------------------------


class TimelineEventSummary(BaseModel):
    """Summary of a single timeline event for dispute reconstruction."""

    event_id: UUID = Field(..., description="Evidence event ID")
    event_type: str = Field(..., description="Type of event (e.g., evt_deposited)")
    event_time: datetime = Field(..., description="When the event occurred")
    actor_type: str = Field(..., description="Type of actor (sender, recipient, system)")
    actor_ref: str = Field(..., description="Reference to the actor")
    description: str = Field(..., description="Human-readable description")
    evidence_object_ids: list[UUID] = Field(
        default_factory=list, description="Associated evidence objects"
    )
    metadata: dict[str, Any] | None = Field(None, description="Event-specific metadata")


class EvidenceVerificationResult(BaseModel):
    """Verification result for a single evidence object."""

    evidence_object_id: UUID = Field(..., description="Evidence object ID")
    status: str = Field(..., description="Verification status (valid/invalid/not_sealed/missing)")
    content_hash_matches: bool | None = Field(None, description="Whether content hash verified")
    has_provider_attestation: bool = Field(..., description="Provider seal present")
    has_time_attestation: bool = Field(..., description="Timestamp token present")
    qualification_label: str = Field(..., description="Qualification status")
    verification_time: datetime = Field(..., description="When verification was performed")
    errors: list[str] = Field(default_factory=list, description="Verification errors")


class TimelineEventWithVerification(BaseModel):
    """Timeline event with evidence verification results."""

    event_id: UUID = Field(..., description="Evidence event ID")
    event_type: str = Field(..., description="Type of event (e.g., evt_deposited)")
    event_time: datetime = Field(..., description="When the event occurred")
    actor_type: str = Field(..., description="Type of actor (sender, recipient, system)")
    actor_ref: str = Field(..., description="Reference to the actor (may be redacted)")
    description: str = Field(..., description="Human-readable description")
    evidence_verifications: list[EvidenceVerificationResult] = Field(
        default_factory=list, description="Verification results for evidence objects"
    )
    event_metadata: dict[str, Any] | None = Field(
        None, description="Event metadata (may be redacted)"
    )
    policy_snapshot_id: UUID | None = Field(None, description="Policy in effect at event time")


class PartyInfoResponse(BaseModel):
    """Party information with redaction support."""

    party_id: UUID = Field(..., description="Party identifier")
    party_type: str = Field(..., description="Party type (natural_person/legal_person)")
    display_name: str = Field(..., description="Display name (may be redacted)")
    email_hash: str | None = Field(None, description="Hashed email for reference")
    identity_ref: str | None = Field(None, description="Identity reference")


class ContentInfoResponse(BaseModel):
    """Content object information with redaction support."""

    content_object_id: UUID = Field(..., description="Content identifier")
    sha256: str = Field(..., description="Content hash for integrity")
    size_bytes: int = Field(..., description="File size in bytes")
    mime_type: str = Field(..., description="Content MIME type")
    original_filename: str | None = Field(None, description="Filename (may be redacted)")


class DeliveryTimelineResponse(BaseModel):
    """Response schema for delivery timeline (dispute reconstruction)."""

    delivery_id: UUID = Field(..., description="Delivery identifier")
    state: str = Field(..., description="Current delivery state")
    sender_party_id: UUID = Field(..., description="Sender party ID")
    recipient_party_id: UUID = Field(..., description="Recipient party ID")
    jurisdiction_profile: str = Field(..., description="Jurisdiction profile")
    created_at: datetime = Field(..., description="Delivery creation time")
    events: list[TimelineEventSummary] = Field(..., description="Ordered list of timeline events")
    content_hashes: list[str] = Field(
        default_factory=list, description="SHA-256 hashes of all content"
    )
    policy_snapshots: list[UUID] = Field(
        default_factory=list, description="Policy snapshots referenced by events"
    )
    generated_at: datetime = Field(..., description="When this timeline was generated")
    generated_by: str = Field(..., description="Admin user who requested timeline")


class DisputeTimelineResponse(BaseModel):
    """Enhanced dispute timeline response with verification and redaction."""

    delivery_id: UUID = Field(..., description="Delivery identifier")
    delivery_state: str = Field(..., description="Current delivery state")
    jurisdiction_profile: str = Field(..., description="Jurisdiction profile")
    sender: PartyInfoResponse = Field(..., description="Sender information")
    recipient: PartyInfoResponse = Field(..., description="Recipient information")
    content_objects: list[ContentInfoResponse] = Field(..., description="Content references")
    events: list[TimelineEventWithVerification] = Field(
        ..., description="Timeline events with verification"
    )
    policy_snapshots: list[UUID] = Field(
        default_factory=list, description="Referenced policy snapshots"
    )
    generated_at: datetime = Field(..., description="When timeline was generated")
    generated_by: str = Field(..., description="Admin who requested timeline")
    redaction_level: str = Field(..., description="Redaction level applied")
    verification_summary: dict[str, int] = Field(..., description="Verification status counts")


class DisclosureExportRequest(BaseModel):
    """Request schema for creating a disclosure export package."""

    export_reason: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Purpose/justification for the disclosure (e.g., court order reference)",
    )
    redaction_level: str = Field(
        "standard",
        pattern=r"^(none|minimal|standard|full)$",
        description="Level of GDPR-compliant redaction to apply",
    )

    model_config = ConfigDict(extra="forbid")


class DisclosureExportResponse(BaseModel):
    """Response schema for disclosure export package."""

    package_id: UUID = Field(..., description="Unique package identifier")
    delivery_id: UUID = Field(..., description="Delivery being disclosed")
    timeline: DisputeTimelineResponse = Field(..., description="Redacted dispute timeline")
    export_reason: str = Field(..., description="Disclosure purpose")
    exported_at: datetime = Field(..., description="Export timestamp")
    exported_by: str = Field(..., description="Admin who created export")
    package_hash: str = Field(..., description="SHA-256 hash of package contents")
    integrity_manifest: dict[str, str] = Field(..., description="Component integrity hashes")


# -----------------------------------------------------------------------------
# Config Snapshot Schemas (REQ-H05)
# -----------------------------------------------------------------------------


class ConfigSnapshotRequest(BaseModel):
    """Request schema for creating a config snapshot."""

    version: str = Field(
        ...,
        min_length=1,
        max_length=50,
        pattern=r"^[a-zA-Z0-9._-]+$",
        description="Version identifier (e.g., 'v1.2.3' or '2024-01-15')",
    )
    description: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Description of changes since previous snapshot",
    )
    config_json: dict[str, Any] = Field(..., description="Configuration values to snapshot")
    doc_refs: dict[str, str] | None = Field(
        None, description="References to policy/CPS documents (key: doc_type, value: storage_ref)"
    )
    make_active: bool = Field(False, description="Whether to make this snapshot the active one")

    model_config = ConfigDict(extra="forbid")


class ConfigSnapshotResponse(BaseModel):
    """Response schema for config snapshot."""

    policy_snapshot_id: UUID = Field(..., description="Unique snapshot identifier")
    version: str = Field(..., description="Version identifier")
    description: str | None = Field(None, description="Change description")
    created_at: datetime = Field(..., description="Creation timestamp")
    created_by: str = Field(..., description="Admin user who created snapshot")
    snapshot_hash: str = Field(..., description="SHA-256 hash of snapshot contents")
    is_active: bool = Field(..., description="Whether this is the active snapshot")
    doc_refs: dict[str, str] | None = Field(None, description="Document references")


# -----------------------------------------------------------------------------
# Access Review Export Schemas (REQ-H06)
# -----------------------------------------------------------------------------


class RoleBindingExport(BaseModel):
    """Export format for a single role binding."""

    binding_id: UUID = Field(..., description="Binding identifier")
    role_name: str = Field(..., description="Role name")
    role_permissions: list[str] = Field(..., description="Permissions granted by role")
    principal_type: str = Field(..., description="Type: admin_user or api_client")
    principal_id: UUID = Field(..., description="User or client ID")
    principal_name: str = Field(..., description="Username or client name")
    granted_at: datetime = Field(..., description="When binding was created")
    granted_by: UUID | None = Field(None, description="Who granted the binding")
    valid_from: datetime | None = Field(None, description="Start of validity period")
    valid_until: datetime | None = Field(None, description="End of validity period")
    last_used_at: datetime | None = Field(None, description="When role was last exercised")
    scope_filter: dict[str, Any] | None = Field(None, description="Scope limitations")
    reason: str | None = Field(None, description="Documented reason for binding")


class PermissionChangeRecord(BaseModel):
    """Record of a permission/role change from audit history."""

    timestamp: datetime = Field(..., description="When the change occurred")
    actor_id: str = Field(..., description="Who made the change")
    actor_type: str = Field(..., description="Type of actor (admin_user, system)")
    target_user_id: str = Field(..., description="User/client affected by the change")
    action: str = Field(..., description="Action: assign or revoke")
    role: str = Field(..., description="Role that was assigned/revoked")
    details: dict[str, Any] | None = Field(None, description="Additional change details")


class AccessReviewExportResponse(BaseModel):
    """Response schema for access review export."""

    exported_at: datetime = Field(..., description="Export timestamp")
    exported_by: str = Field(..., description="Admin user who exported")
    total_bindings: int = Field(..., description="Total number of role bindings")
    total_users: int = Field(..., description="Total admin users with bindings")
    total_clients: int = Field(..., description="Total API clients with bindings")
    bindings: list[RoleBindingExport] = Field(..., description="All role bindings for review")
    inactive_users: list[UUID] = Field(
        default_factory=list, description="Users with no activity in review period"
    )
    inactive_clients: list[UUID] = Field(
        default_factory=list, description="Clients with no activity in review period"
    )
    permission_changes: list[PermissionChangeRecord] = Field(
        default_factory=list, description="History of permission changes from audit log"
    )


# -----------------------------------------------------------------------------
# Incident Management Schemas (REQ-H04)
# -----------------------------------------------------------------------------


class CreateIncidentRequest(BaseModel):
    """Request schema for creating an incident record."""

    title: str = Field(
        ...,
        min_length=5,
        max_length=200,
        description="Brief incident title",
    )
    severity: str = Field(
        ...,
        pattern=r"^(critical|high|medium|low)$",
        description="Incident severity level",
    )
    category: str = Field(
        ...,
        pattern=r"^(security|availability|integrity|confidentiality|compliance|other)$",
        description="Incident category",
    )
    description: str = Field(
        ...,
        min_length=20,
        max_length=5000,
        description="Detailed incident description",
    )
    detected_at: datetime = Field(..., description="When the incident was detected")
    affected_deliveries: list[UUID] | None = Field(
        None, description="List of affected delivery IDs"
    )
    initial_assessment: str | None = Field(
        None,
        max_length=2000,
        description="Initial assessment of impact and scope",
    )

    model_config = ConfigDict(extra="forbid")


class IncidentResponse(BaseModel):
    """Response schema for incident record."""

    incident_id: UUID = Field(..., description="Unique incident identifier")
    title: str = Field(..., description="Incident title")
    severity: str = Field(..., description="Severity level")
    category: str = Field(..., description="Incident category")
    status: str = Field(..., description="Current status (open, investigating, resolved, closed)")
    description: str = Field(..., description="Incident description")
    detected_at: datetime = Field(..., description="Detection timestamp")
    created_at: datetime = Field(..., description="Record creation timestamp")
    created_by: str = Field(..., description="Admin who created the record")
    affected_deliveries: list[UUID] = Field(
        default_factory=list, description="Affected delivery IDs"
    )
    resolved_at: datetime | None = Field(None, description="Resolution timestamp")


class IncidentExportResponse(BaseModel):
    """Response schema for incident timeline export."""

    incident_id: UUID = Field(..., description="Incident identifier")
    title: str = Field(..., description="Incident title")
    severity: str = Field(..., description="Severity level")
    category: str = Field(..., description="Incident category")
    status: str = Field(..., description="Current status")
    description: str = Field(..., description="Incident description")
    detected_at: datetime = Field(..., description="Detection timestamp")
    created_at: datetime = Field(..., description="Record creation timestamp")
    created_by: str = Field(..., description="Admin who created the record")
    resolved_at: datetime | None = Field(None, description="Resolution timestamp")
    affected_deliveries: list[DeliveryIncidentSummary] = Field(
        default_factory=list, description="Summary of affected deliveries"
    )
    timeline_events: list[IncidentTimelineEvent] = Field(
        ..., description="Chronological incident events"
    )
    exported_at: datetime = Field(..., description="Export timestamp")
    exported_by: str = Field(..., description="Admin who exported")
    export_hash: str = Field(..., description="SHA-256 hash of export contents")


class DeliveryIncidentSummary(BaseModel):
    """Summary of a delivery affected by an incident."""

    delivery_id: UUID = Field(..., description="Delivery identifier")
    state: str = Field(..., description="Delivery state at time of incident")
    sender_party_id: UUID = Field(..., description="Sender party ID")
    recipient_party_id: UUID = Field(..., description="Recipient party ID")
    created_at: datetime = Field(..., description="Delivery creation time")


class IncidentTimelineEvent(BaseModel):
    """Event in an incident timeline."""

    timestamp: datetime = Field(..., description="Event timestamp")
    event_type: str = Field(..., description="Type of event")
    actor: str = Field(..., description="Who performed the action")
    description: str = Field(..., description="Event description")
    metadata: dict[str, Any] | None = Field(None, description="Additional event data")


# -----------------------------------------------------------------------------
# System Statistics Schemas
# -----------------------------------------------------------------------------


class SystemStatsResponse(BaseModel):
    """Response schema for system statistics."""

    generated_at: datetime = Field(..., description="Statistics generation timestamp")
    delivery_stats: DeliveryStats = Field(..., description="Delivery-related statistics")
    evidence_stats: EvidenceStats = Field(..., description="Evidence-related statistics")
    user_stats: UserStats = Field(..., description="User and client statistics")
    storage_stats: StorageStats = Field(..., description="Storage utilization statistics")


class DeliveryStats(BaseModel):
    """Delivery-related statistics."""

    total_deliveries: int = Field(0, description="Total delivery count")
    by_state: dict[str, int] = Field(default_factory=dict, description="Count by delivery state")
    by_jurisdiction: dict[str, int] = Field(
        default_factory=dict, description="Count by jurisdiction profile"
    )
    created_today: int = Field(0, description="Deliveries created today")
    created_this_week: int = Field(0, description="Deliveries created this week")
    created_this_month: int = Field(0, description="Deliveries created this month")
    average_time_to_accept_hours: float | None = Field(
        None, description="Average time to acceptance in hours"
    )


class EvidenceStats(BaseModel):
    """Evidence-related statistics."""

    total_evidence_events: int = Field(0, description="Total evidence event count")
    total_evidence_objects: int = Field(0, description="Total evidence object count")
    qualified_count: int = Field(0, description="Qualified evidence objects")
    non_qualified_count: int = Field(0, description="Non-qualified evidence objects")
    by_event_type: dict[str, int] = Field(default_factory=dict, description="Count by event type")


class UserStats(BaseModel):
    """User and client statistics."""

    total_admin_users: int = Field(0, description="Total admin users")
    active_admin_users: int = Field(0, description="Active admin users")
    total_api_clients: int = Field(0, description="Total API clients")
    active_api_clients: int = Field(0, description="Active API clients")
    total_parties: int = Field(0, description="Total parties (senders/recipients)")


class StorageStats(BaseModel):
    """Storage utilization statistics."""

    total_content_objects: int = Field(0, description="Total content objects")
    total_content_size_bytes: int = Field(0, description="Total content size in bytes")
    total_evidence_blobs: int = Field(0, description="Total evidence blobs stored")
    audit_log_record_count: int = Field(0, description="Total audit log records")


# -----------------------------------------------------------------------------
# Conformity Package Schemas (REQ-A02)
# -----------------------------------------------------------------------------


class ConformityPackageRequest(BaseModel):
    """Request schema for generating a conformity assessment package.

    Conformity packages are comprehensive exports containing all material
    needed for auditors performing QERDS/LRE certification assessments.
    """

    assessment_type: str = Field(
        ...,
        pattern=r"^(initial|periodic|ad-hoc|recertification)$",
        description="Type of assessment (initial, periodic, ad-hoc, recertification)",
    )
    include_evidence_samples: bool = Field(
        True, description="Include sample evidence events in the package"
    )
    include_key_ceremonies: bool = Field(True, description="Include key lifecycle ceremony events")
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Reason for generating the package (for audit trail)",
    )

    model_config = ConfigDict(extra="forbid")


class TraceabilityEntryResponse(BaseModel):
    """Response schema for a single traceability matrix entry."""

    requirement_id: str = Field(..., description="Requirement identifier (e.g., REQ-A01)")
    title: str = Field(..., description="Human-readable requirement title")
    category: str = Field(..., description="Requirement category")
    modules: list[str] = Field(default_factory=list, description="Implementation module paths")
    tests: list[str] = Field(default_factory=list, description="Test file paths")
    evidence: list[str] = Field(default_factory=list, description="Evidence artifact descriptions")
    implementation_status: str = Field(..., description="Current implementation status")


class PolicyDocumentResponse(BaseModel):
    """Response schema for a policy document reference."""

    doc_id: str = Field(..., description="Document identifier")
    title: str = Field(..., description="Document title")
    path: str = Field(..., description="Path to document in repository")
    publication_status: str = Field(..., description="Publication status (published/internal)")
    content_hash: str = Field(..., description="SHA-256 hash of document content")
    last_modified: datetime | None = Field(None, description="Last modification timestamp")


class ConformityPackageResponse(BaseModel):
    """Response schema for conformity package generation."""

    package_id: UUID = Field(..., description="Unique identifier for the package")
    assessment_type: str = Field(..., description="Type of assessment")
    created_at: datetime = Field(..., description="When the package was generated")
    created_by: str = Field(..., description="Admin user who created the package")
    requirement_count: int = Field(0, description="Number of requirements in traceability matrix")
    policy_document_count: int = Field(0, description="Number of policy documents")
    evidence_sample_count: int = Field(0, description="Number of evidence samples")
    config_snapshot_count: int = Field(0, description="Number of configuration snapshots")
    key_count: int = Field(0, description="Number of keys in inventory")
    ceremony_event_count: int = Field(0, description="Number of key ceremony events")
    package_hash: str = Field(..., description="SHA-256 hash of the package contents")
    storage_ref: str = Field(..., description="Reference to stored package")
    qualification_label: str = Field(
        ..., description="Qualification status (qualified/non_qualified)"
    )


class TraceabilityMatrixResponse(BaseModel):
    """Response schema for traceability matrix export."""

    generated_at: datetime = Field(..., description="When the matrix was generated")
    generated_by: str = Field(..., description="Admin user who requested the matrix")
    total_requirements: int = Field(..., description="Total number of requirements")
    by_category: dict[str, int] = Field(default_factory=dict, description="Count by category")
    by_status: dict[str, int] = Field(
        default_factory=dict, description="Count by implementation status"
    )
    entries: list[TraceabilityEntryResponse] = Field(..., description="All traceability entries")


# -----------------------------------------------------------------------------
# DR Evidence Schemas (REQ-D09, REQ-H08)
# -----------------------------------------------------------------------------


class BackupScopeSchema(BaseModel):
    """Schema for backup scope configuration."""

    postgresql: bool = Field(True, description="Include PostgreSQL database")
    object_store: bool = Field(True, description="Include object store (MinIO/S3)")
    audit_logs: bool = Field(True, description="Include audit logs")
    config: bool = Field(True, description="Include configuration")


class RPOTargetSchema(BaseModel):
    """Schema for RPO (Recovery Point Objective) target and measurement."""

    target_minutes: int = Field(..., ge=1, description="Target RPO in minutes")
    measured_minutes: float | None = Field(None, ge=0, description="Actual measured RPO in minutes")
    meets_target: bool | None = Field(None, description="Whether the measured RPO meets the target")


class RTOTargetSchema(BaseModel):
    """Schema for RTO (Recovery Time Objective) target and measurement."""

    target_minutes: int = Field(..., ge=1, description="Target RTO in minutes")
    measured_minutes: float | None = Field(None, ge=0, description="Actual measured RTO in minutes")
    meets_target: bool | None = Field(None, description="Whether the measured RTO meets the target")


class RecordBackupExecutionRequest(BaseModel):
    """Request schema for recording a backup execution."""

    outcome: str = Field(
        ...,
        pattern=r"^(success|partial|failure|in_progress)$",
        description="Outcome of the backup operation",
    )
    backup_scope: BackupScopeSchema | None = Field(
        None, description="What was included in the backup"
    )
    duration_seconds: int | None = Field(None, ge=0, description="How long the backup took")
    summary: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Human-readable summary of the backup operation",
    )
    details: dict[str, Any] | None = Field(
        None, description="Detailed structured data about the operation"
    )
    executed_at: datetime | None = Field(
        None, description="When the backup was executed (defaults to now)"
    )

    model_config = ConfigDict(extra="forbid")


class RecordRestoreTestRequest(BaseModel):
    """Request schema for recording a restore test."""

    outcome: str = Field(
        ...,
        pattern=r"^(success|partial|failure|in_progress)$",
        description="Outcome of the restore test",
    )
    backup_scope: BackupScopeSchema | None = Field(None, description="What was restored")
    duration_seconds: int | None = Field(None, ge=0, description="How long the restore took")
    summary: str = Field(
        ...,
        min_length=10,
        max_length=1000,
        description="Human-readable summary of the restore test",
    )
    details: dict[str, Any] | None = Field(
        None, description="Detailed structured data about the operation"
    )
    executed_at: datetime | None = Field(
        None, description="When the test was executed (defaults to now)"
    )

    model_config = ConfigDict(extra="forbid")


class RecordDRDrillRequest(BaseModel):
    """Request schema for recording a DR drill/exercise."""

    outcome: str = Field(
        ...,
        pattern=r"^(success|partial|failure|in_progress)$",
        description="Outcome of the DR drill",
    )
    duration_seconds: int | None = Field(None, ge=0, description="Total duration of the drill")
    rpo: RPOTargetSchema | None = Field(None, description="RPO target and measured value")
    rto: RTOTargetSchema | None = Field(None, description="RTO target and measured value")
    summary: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="Human-readable summary of the DR drill",
    )
    details: dict[str, Any] | None = Field(
        None, description="Detailed structured data (runbook steps, participants, etc.)"
    )
    executed_at: datetime | None = Field(
        None, description="When the drill was executed (defaults to now)"
    )

    model_config = ConfigDict(extra="forbid")


class DREvidenceRecordResponse(BaseModel):
    """Response schema for a DR evidence record."""

    record_id: UUID = Field(..., description="Unique identifier for the record")
    evidence_type: str = Field(
        ..., description="Type of evidence (backup_execution, restore_test, dr_drill)"
    )
    outcome: str = Field(..., description="Outcome of the operation")
    executed_at: datetime = Field(..., description="When the operation was executed")
    executed_by: str = Field(..., description="Who executed the operation")
    duration_seconds: int | None = Field(None, description="Duration in seconds")
    backup_scope: BackupScopeSchema | None = Field(None, description="Backup scope")
    rpo: RPOTargetSchema | None = Field(None, description="RPO target and measurement")
    rto: RTOTargetSchema | None = Field(None, description="RTO target and measurement")
    summary: str = Field(..., description="Human-readable summary")
    details: dict[str, Any] = Field(default_factory=dict, description="Detailed data")
    artifact_refs: list[str] = Field(
        default_factory=list, description="References to stored artifacts"
    )
    record_hash: str = Field(..., description="SHA-256 hash of the record")
    created_at: datetime = Field(..., description="When this record was created")


class DREvidenceSummaryResponse(BaseModel):
    """Response schema for DR evidence summary."""

    period_start: datetime = Field(..., description="Start of the summary period")
    period_end: datetime = Field(..., description="End of the summary period")
    backup_count: int = Field(0, description="Number of backup executions")
    restore_test_count: int = Field(0, description="Number of restore tests")
    dr_drill_count: int = Field(0, description="Number of DR drills")
    success_rate: float = Field(0.0, description="Percentage of successful operations")
    last_successful_backup: datetime | None = Field(None, description="Last successful backup")
    last_restore_test: datetime | None = Field(None, description="Last restore test")
    last_dr_drill: datetime | None = Field(None, description="Last DR drill")
    rpo_compliance: bool | None = Field(None, description="Whether RPO targets are being met")
    rto_compliance: bool | None = Field(None, description="Whether RTO targets are being met")


class DREvidenceListResponse(BaseModel):
    """Response schema for listing DR evidence records."""

    records: list[DREvidenceRecordResponse] = Field(..., description="List of evidence records")
    total_count: int = Field(..., description="Total number of records matching the filter")


# -----------------------------------------------------------------------------
# Common Response Schemas
# -----------------------------------------------------------------------------


class AdminActionResponse(BaseModel):
    """Generic response for admin actions."""

    success: bool = Field(..., description="Whether the action succeeded")
    message: str = Field(..., description="Human-readable result message")
    action_id: UUID | None = Field(None, description="ID of the action for audit reference")
    timestamp: datetime = Field(..., description="When the action was performed")


class ErrorResponse(BaseModel):
    """Standard error response schema."""

    error: str = Field(..., description="Error type/code")
    message: str = Field(..., description="Human-readable error message")
    details: dict[str, Any] | None = Field(None, description="Additional error details")
