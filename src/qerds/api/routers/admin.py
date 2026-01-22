"""Admin API router.

Handles operational and administrative endpoints.
All endpoints require admin authentication and RBAC.

Covers requirements: REQ-A02, REQ-D02, REQ-D08, REQ-D09, REQ-H01, REQ-H03,
REQ-H04, REQ-H05, REQ-H06, REQ-H08, REQ-H10
See specs/implementation/35-apis.md for API design.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Any

if TYPE_CHECKING:
    from qerds.services.conformity_package import ConformityPackageService
    from qerds.services.dr_evidence import DREvidenceRecord, DREvidenceService

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from qerds.api.middleware.auth import AuthenticatedUser, require_role
from qerds.api.schemas.admin import (
    AccessReviewExportResponse,
    AuditPackRequest,
    AuditPackResponse,
    AuditPackVerification,
    BackupScopeSchema,
    ConfigSnapshotRequest,
    ConfigSnapshotResponse,
    ConformityPackageRequest,
    ConformityPackageResponse,
    ContentInfoResponse,
    CreateIncidentRequest,
    DeliveryIncidentSummary,
    DeliveryStats,
    DeliveryTimelineResponse,
    DisclosureExportRequest,
    DisclosureExportResponse,
    DisputeTimelineResponse,
    DREvidenceListResponse,
    DREvidenceRecordResponse,
    DREvidenceSummaryResponse,
    EvidenceStats,
    EvidenceVerificationResult,
    IncidentExportResponse,
    IncidentResponse,
    IncidentTimelineEvent,
    PartyInfoResponse,
    PermissionChangeRecord,
    RecordBackupExecutionRequest,
    RecordDRDrillRequest,
    RecordRestoreTestRequest,
    RoleBindingExport,
    RPOTargetSchema,
    RTOTargetSchema,
    StorageStats,
    SystemStatsResponse,
    TimelineEventSummary,
    TimelineEventWithVerification,
    TraceabilityEntryResponse,
    TraceabilityMatrixResponse,
    UserStats,
)
from qerds.db.models.base import QualificationLabel
from qerds.db.models.deliveries import ContentObject, Delivery
from qerds.db.models.evidence import EvidenceEvent, EvidenceObject, PolicySnapshot
from qerds.services.audit_pack import AuditPackService
from qerds.services.dispute import DisputeService
from qerds.services.security_events import SecurityActor, SecurityEventLogger

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    responses={
        401: {"description": "Admin authentication required"},
        403: {"description": "Insufficient admin permissions"},
    },
)


# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------


async def get_db_session() -> AsyncSession:
    """Get database session.

    Uses the application's async session factory.
    """
    from qerds.db import get_async_session

    async with get_async_session() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]

# Require admin_user role for all admin endpoints
AdminUser = Annotated[AuthenticatedUser, Depends(require_role("admin_user"))]


async def get_audit_pack_service(db: DbSession) -> AuditPackService:
    """Get the audit pack service with required dependencies.

    Initializes the trust service and object store for audit pack generation.
    """
    from pathlib import Path

    from qerds.core.settings import get_settings
    from qerds.services.storage import ObjectStoreClient
    from qerds.services.trust import QualificationMode, TrustService, TrustServiceConfig

    settings = get_settings()

    # Initialize trust service
    trust_config = TrustServiceConfig(
        mode=QualificationMode(settings.claim_state.value),
        key_storage_path=Path(settings.trust.key_storage_path),
    )
    trust_service = TrustService(trust_config)
    await trust_service.initialize()

    # Initialize object store
    object_store = ObjectStoreClient.from_settings(settings.s3)

    return AuditPackService(db, trust_service, object_store)


def _get_security_actor(user: AuthenticatedUser, request: Request) -> SecurityActor:  # noqa: ARG001
    """Build a SecurityActor from the authenticated user and request.

    Args:
        user: The authenticated admin user.
        request: The HTTP request (reserved for future use to extract additional context).

    Returns:
        SecurityActor for audit logging.
    """
    return SecurityActor(
        actor_id=str(user.principal_id),
        actor_type=user.principal_type,
        ip_address=user.ip_address,
        user_agent=user.user_agent,
        session_id=str(user.session_id) if user.session_id else None,
    )


# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for admin namespace.

    Returns:
        Health status for the admin API subsystem.
    """
    return {"status": "healthy", "namespace": "admin"}


# -----------------------------------------------------------------------------
# Audit Pack Generation (REQ-H01)
# -----------------------------------------------------------------------------


@router.post(
    "/audit-packs",
    response_model=AuditPackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate audit pack",
    description="Generate comprehensive audit pack for a date range with evidence and logs.",
)
async def generate_audit_pack(
    request_body: AuditPackRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> AuditPackResponse:
    """Generate an audit pack for a specified date range.

    Creates a comprehensive audit pack containing:
    - Evidence samples with verification bundles
    - Audit log integrity proofs
    - Configuration snapshots
    - Cryptographic parameters
    - Key inventory metadata
    - Policy document references
    - Release/SBOM metadata

    The pack is sealed and timestamped, then stored to object storage.

    Args:
        request_body: Audit pack generation parameters.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Audit pack details with storage reference and verification results.
    """
    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="generate_audit_pack",
        target_type="audit_pack",
        target_id=f"{request_body.start_date}_{request_body.end_date}",
        details={
            "start_date": request_body.start_date.isoformat(),
            "end_date": request_body.end_date.isoformat(),
            "reason": request_body.reason,
        },
    )

    try:
        # Get audit pack service
        audit_pack_service = await get_audit_pack_service(db)

        # Generate the sealed audit pack
        sealed_pack = await audit_pack_service.generate_audit_pack(
            start_date=request_body.start_date,
            end_date=request_body.end_date,
            created_by=str(user.principal_id),
            reason=request_body.reason,
            include_evidence=request_body.include_evidence,
            include_security_logs=request_body.include_security_logs,
            include_ops_logs=request_body.include_ops_logs,
            include_config_snapshots=request_body.include_config_snapshots,
        )

        await db.commit()

        return AuditPackResponse(
            pack_id=sealed_pack.pack_id,
            start_date=sealed_pack.start_date,
            end_date=sealed_pack.end_date,
            created_at=sealed_pack.created_at,
            created_by=sealed_pack.created_by,
            evidence_count=sealed_pack.contents_summary.get("evidence_count", 0),
            security_log_count=sealed_pack.contents_summary.get("security_log_count", 0),
            ops_log_count=sealed_pack.contents_summary.get("ops_log_count", 0),
            config_snapshot_count=sealed_pack.contents_summary.get("config_snapshot_count", 0),
            pack_hash=sealed_pack.pack_hash,
            storage_ref=sealed_pack.storage_ref,
            verification=AuditPackVerification(
                evidence_chain_valid=sealed_pack.verification.get("evidence_chain_valid", True),
                security_chain_valid=sealed_pack.verification.get("security_chain_valid", True),
                ops_chain_valid=sealed_pack.verification.get("ops_chain_valid", True),
                errors=sealed_pack.verification.get("errors", []),
            ),
        )
    except Exception as e:
        logger.exception("Failed to generate audit pack: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate audit pack: {e!s}",
        ) from e


# -----------------------------------------------------------------------------
# Delivery Timeline / Dispute Reconstruction (REQ-H10)
# -----------------------------------------------------------------------------


@router.get(
    "/deliveries/{delivery_id}/timeline",
    response_model=DeliveryTimelineResponse,
    summary="Get delivery timeline",
    description="Retrieve complete timeline for dispute reconstruction with all evidence events.",
)
async def get_delivery_timeline(
    delivery_id: uuid.UUID,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> DeliveryTimelineResponse:
    """Get complete timeline for a delivery for dispute reconstruction.

    Retrieves all evidence events, policy snapshots, and content hashes
    for comprehensive dispute analysis.

    Args:
        delivery_id: UUID of the delivery.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Complete delivery timeline with all events and metadata.

    Raises:
        HTTPException: If delivery not found.
    """
    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="view_delivery_timeline",
        target_type="delivery",
        target_id=str(delivery_id),
        details={"purpose": "dispute_reconstruction"},
    )

    # Get delivery with relationships
    query = (
        select(Delivery)
        .where(Delivery.delivery_id == delivery_id)
        .options(
            selectinload(Delivery.content_objects),
            selectinload(Delivery.evidence_events).selectinload(EvidenceEvent.evidence_objects),
        )
    )
    result = await db.execute(query)
    delivery = result.scalar_one_or_none()

    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delivery {delivery_id} not found",
        )

    # Build timeline events
    events: list[TimelineEventSummary] = []
    policy_snapshot_ids: set[uuid.UUID] = set()

    for event in sorted(delivery.evidence_events, key=lambda e: e.event_time):
        evidence_object_ids = [eo.evidence_object_id for eo in event.evidence_objects]

        if event.policy_snapshot_id:
            policy_snapshot_ids.add(event.policy_snapshot_id)

        events.append(
            TimelineEventSummary(
                event_id=event.event_id,
                event_type=event.event_type.value,
                event_time=event.event_time,
                actor_type=event.actor_type.value,
                actor_ref=event.actor_ref,
                description=_get_event_description(event),
                evidence_object_ids=evidence_object_ids,
                metadata=event.event_metadata,
            )
        )

    # Collect content hashes
    content_hashes = [co.sha256 for co in delivery.content_objects]

    await db.commit()

    return DeliveryTimelineResponse(
        delivery_id=delivery.delivery_id,
        state=delivery.state.value,
        sender_party_id=delivery.sender_party_id,
        recipient_party_id=delivery.recipient_party_id,
        jurisdiction_profile=delivery.jurisdiction_profile,
        created_at=delivery.created_at,
        events=events,
        content_hashes=content_hashes,
        policy_snapshots=list(policy_snapshot_ids),
        generated_at=datetime.now(UTC),
        generated_by=str(user.principal_id),
    )


def _get_event_description(event: EvidenceEvent) -> str:
    """Generate human-readable description for an evidence event.

    Uses the canonical EVENT_DESCRIPTIONS from DisputeService to avoid duplication.

    Args:
        event: The evidence event.

    Returns:
        Human-readable description string.
    """
    return DisputeService.EVENT_DESCRIPTIONS.get(
        event.event_type.value, f"Event: {event.event_type.value}"
    )


@router.post(
    "/deliveries/{delivery_id}/export",
    response_model=DisclosureExportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create disclosure export",
    description="Create a GDPR-compliant disclosure package for external parties.",
)
async def create_disclosure_export(
    delivery_id: uuid.UUID,
    request_body: DisclosureExportRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> DisclosureExportResponse:
    """Create a controlled disclosure export package.

    Generates a self-contained package suitable for disclosure to courts,
    regulators, or other authorized third parties. Includes GDPR-compliant
    redaction and integrity hashing per REQ-H10.

    Args:
        delivery_id: UUID of the delivery to export.
        request_body: Export parameters including reason and redaction level.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        DisclosureExportResponse with redacted timeline and integrity hashes.

    Raises:
        HTTPException: If delivery not found.
    """
    from qerds.services.dispute import (
        DeliveryNotFoundError,
        DisputeService,
        RedactionLevel,
    )

    # Log the admin action (sensitive export operation)
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_sensitive_access(
        actor=actor,
        resource_type="delivery",
        resource_id=str(delivery_id),
        access_type="disclosure_export",
        purpose=request_body.export_reason[:200],
        details={
            "redaction_level": request_body.redaction_level,
        },
    )

    # Map redaction level from request
    try:
        redaction_level = RedactionLevel(request_body.redaction_level)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid redaction level: {request_body.redaction_level}",
        ) from e

    # Create disclosure package using the dispute service
    service = DisputeService(db)
    try:
        package = await service.create_disclosure_package(
            delivery_id=delivery_id,
            exported_by=str(user.principal_id),
            export_reason=request_body.export_reason,
            redaction_level=redaction_level,
        )
    except DeliveryNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delivery {delivery_id} not found",
        ) from e

    await db.commit()

    # Convert service response to API response
    timeline = package.timeline
    return DisclosureExportResponse(
        package_id=package.package_id,
        delivery_id=package.delivery_id,
        timeline=DisputeTimelineResponse(
            delivery_id=timeline.delivery_id,
            delivery_state=timeline.delivery_state,
            jurisdiction_profile=timeline.jurisdiction_profile,
            sender=PartyInfoResponse(
                party_id=timeline.sender.party_id,
                party_type=timeline.sender.party_type,
                display_name=timeline.sender.display_name,
                email_hash=timeline.sender.email_hash,
                identity_ref=timeline.sender.identity_ref,
            ),
            recipient=PartyInfoResponse(
                party_id=timeline.recipient.party_id,
                party_type=timeline.recipient.party_type,
                display_name=timeline.recipient.display_name,
                email_hash=timeline.recipient.email_hash,
                identity_ref=timeline.recipient.identity_ref,
            ),
            content_objects=[
                ContentInfoResponse(
                    content_object_id=co.content_object_id,
                    sha256=co.sha256,
                    size_bytes=co.size_bytes,
                    mime_type=co.mime_type,
                    original_filename=co.original_filename,
                )
                for co in timeline.content_objects
            ],
            events=[
                TimelineEventWithVerification(
                    event_id=e.event_id,
                    event_type=e.event_type,
                    event_time=e.event_time,
                    actor_type=e.actor_type,
                    actor_ref=e.actor_ref,
                    description=e.description,
                    evidence_verifications=[
                        EvidenceVerificationResult(
                            evidence_object_id=ev.evidence_object_id,
                            status=ev.status.value,
                            content_hash_matches=ev.content_hash_matches,
                            has_provider_attestation=ev.has_provider_attestation,
                            has_time_attestation=ev.has_time_attestation,
                            qualification_label=ev.qualification_label,
                            verification_time=ev.verification_time,
                            errors=ev.errors,
                        )
                        for ev in e.evidence_verifications
                    ],
                    event_metadata=e.event_metadata,
                    policy_snapshot_id=e.policy_snapshot_id,
                )
                for e in timeline.events
            ],
            policy_snapshots=timeline.policy_snapshots,
            generated_at=timeline.generated_at,
            generated_by=timeline.generated_by,
            redaction_level=timeline.redaction_level.value,
            verification_summary=timeline.verification_summary,
        ),
        export_reason=package.export_reason,
        exported_at=package.exported_at,
        exported_by=package.exported_by,
        package_hash=package.package_hash,
        integrity_manifest=package.integrity_manifest,
    )


# -----------------------------------------------------------------------------
# Config Snapshots (REQ-H05)
# -----------------------------------------------------------------------------


@router.post(
    "/config/snapshots",
    response_model=ConfigSnapshotResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create config snapshot",
    description="Create a versioned configuration snapshot. Changes are logged for audit.",
)
async def create_config_snapshot(
    request_body: ConfigSnapshotRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> ConfigSnapshotResponse:
    """Create a versioned configuration snapshot.

    Captures the current configuration state with version identifier
    and description of changes. Used for policy/config audit trail.

    Args:
        request_body: Config snapshot parameters.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Created config snapshot details.
    """
    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_config_change(
        actor=actor,
        config_key="policy_snapshot",
        new_value=request_body.version,
        details={
            "description": request_body.description,
            "make_active": request_body.make_active,
        },
    )

    # Compute snapshot hash
    snapshot_data = {
        "version": request_body.version,
        "config_json": request_body.config_json,
        "doc_refs": request_body.doc_refs,
    }
    snapshot_hash = hashlib.sha256(
        json.dumps(snapshot_data, sort_keys=True, default=str).encode()
    ).hexdigest()

    # If making active, deactivate current active snapshot
    if request_body.make_active:
        await db.execute(
            select(PolicySnapshot)
            .where(PolicySnapshot.is_active.is_(True))
            .execution_options(synchronize_session="fetch")
        )
        # Update in a separate query since we're using async
        from sqlalchemy import update

        await db.execute(
            update(PolicySnapshot).where(PolicySnapshot.is_active.is_(True)).values(is_active=False)
        )

    # Create the snapshot
    snapshot = PolicySnapshot(
        created_by=str(user.principal_id),
        version=request_body.version,
        description=request_body.description,
        config_json=request_body.config_json,
        doc_refs=request_body.doc_refs,
        snapshot_hash=snapshot_hash,
        is_active=request_body.make_active,
    )

    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)

    logger.info(
        "Config snapshot created",
        extra={
            "snapshot_id": str(snapshot.policy_snapshot_id),
            "version": request_body.version,
            "created_by": str(user.principal_id),
        },
    )

    return ConfigSnapshotResponse(
        policy_snapshot_id=snapshot.policy_snapshot_id,
        version=snapshot.version,
        description=snapshot.description,
        created_at=snapshot.created_at,
        created_by=str(user.principal_id),
        snapshot_hash=snapshot.snapshot_hash or snapshot_hash,
        is_active=snapshot.is_active,
        doc_refs=snapshot.doc_refs,
    )


# -----------------------------------------------------------------------------
# Access Review Export (REQ-H06)
# -----------------------------------------------------------------------------


async def _get_permission_change_history(
    db: AsyncSession,
    limit: int = 1000,
) -> list[PermissionChangeRecord]:
    """Fetch permission change history from the security audit log.

    Retrieves records of role assignments and revocations from the
    tamper-evident audit log for compliance review.

    Args:
        db: Database session.
        limit: Maximum number of records to return.

    Returns:
        List of permission change records, ordered by timestamp descending.
    """
    from qerds.db.models.audit import AuditLogRecord
    from qerds.db.models.base import AuditStream

    # Query audit log for role change events
    # Event types: admin_role_assigned, admin_role_revoked
    role_change_events = ["admin_role_assigned", "admin_role_revoked"]

    query = (
        select(AuditLogRecord)
        .where(AuditLogRecord.stream == AuditStream.SECURITY)
        .where(AuditLogRecord.event_type.in_(role_change_events))
        .order_by(AuditLogRecord.created_at.desc())
        .limit(limit)
    )

    result = await db.execute(query)
    records = result.scalars().all()

    permission_changes: list[PermissionChangeRecord] = []

    for record in records:
        # Extract details from the summary field which contains structured data
        summary = record.summary or {}

        # Determine action from event type
        action = "assign" if record.event_type == "admin_role_assigned" else "revoke"

        # The summary typically contains the action and resource info
        # The payload_ref contains full details but is stored externally
        # For now, we use what's available in summary and resource fields
        role_name = summary.get("resource", "").split("/")[-1] if summary.get("resource") else ""

        # Parse role from action string if available (format: "role assign: <role_name>")
        action_str = summary.get("action", "")
        if ":" in action_str:
            role_name = action_str.split(":")[-1].strip()

        permission_changes.append(
            PermissionChangeRecord(
                timestamp=record.created_at,
                actor_id=record.actor_id or "unknown",
                actor_type=record.actor_type or "unknown",
                target_user_id=record.resource_id or "unknown",
                action=action,
                role=role_name or "unknown",
                details=summary,
            )
        )

    return permission_changes


@router.get(
    "/access-reviews/export",
    response_model=AccessReviewExportResponse,
    summary="Export RBAC bindings",
    description="Export all role bindings with last-used timestamps for access review.",
)
async def export_access_reviews(
    user: AdminUser,
    db: DbSession,
    request: Request,
    inactive_days: Annotated[
        int, Query(ge=1, le=365, description="Days of inactivity to flag")
    ] = 90,
) -> AccessReviewExportResponse:
    """Export RBAC bindings for access review.

    Generates a comprehensive export of all role bindings including
    last-used timestamps to identify inactive accounts.

    Args:
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.
        inactive_days: Number of days without activity to flag as inactive.

    Returns:
        Complete role binding export for review.
    """
    from qerds.db.models.auth import RoleBinding

    # Log the admin action (sensitive export)
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_sensitive_access(
        actor=actor,
        resource_type="rbac_bindings",
        resource_id="all",
        access_type="export",
        purpose="access_review",
    )

    # Get all role bindings with related data
    bindings_query = (
        select(RoleBinding)
        .options(
            selectinload(RoleBinding.role),
            selectinload(RoleBinding.admin_user),
            selectinload(RoleBinding.api_client),
        )
        .order_by(RoleBinding.created_at)
    )
    result = await db.execute(bindings_query)
    bindings = result.scalars().all()

    # Build export records
    binding_exports: list[RoleBindingExport] = []
    user_ids: set[uuid.UUID] = set()
    client_ids: set[uuid.UUID] = set()
    inactive_threshold = datetime.now(UTC) - timedelta(days=inactive_days)

    for binding in bindings:
        if binding.admin_user_id:
            user_ids.add(binding.admin_user_id)
            principal_type = "admin_user"
            principal_id = binding.admin_user_id
            principal_name = binding.admin_user.username if binding.admin_user else "Unknown"
            last_used = binding.admin_user.last_login_at if binding.admin_user else None
        elif binding.api_client_id:
            client_ids.add(binding.api_client_id)
            principal_type = "api_client"
            principal_id = binding.api_client_id
            principal_name = binding.api_client.name if binding.api_client else "Unknown"
            last_used = binding.api_client.last_used_at if binding.api_client else None
        else:
            continue  # Skip invalid bindings

        binding_exports.append(
            RoleBindingExport(
                binding_id=binding.binding_id,
                role_name=binding.role.name if binding.role else "Unknown",
                role_permissions=binding.role.permissions if binding.role else [],
                principal_type=principal_type,
                principal_id=principal_id,
                principal_name=principal_name,
                granted_at=binding.created_at,
                granted_by=binding.granted_by,
                valid_from=binding.valid_from,
                valid_until=binding.valid_until,
                last_used_at=last_used,
                scope_filter=binding.scope_filter,
                reason=binding.reason,
            )
        )

    # Find inactive users and clients
    inactive_users: list[uuid.UUID] = []
    inactive_clients: list[uuid.UUID] = []

    for binding in bindings:
        if binding.admin_user_id and binding.admin_user:
            last_login = binding.admin_user.last_login_at
            is_inactive = not last_login or last_login < inactive_threshold
            if is_inactive and binding.admin_user_id not in inactive_users:
                inactive_users.append(binding.admin_user_id)
        elif binding.api_client_id and binding.api_client:
            last_used = binding.api_client.last_used_at
            is_inactive = not last_used or last_used < inactive_threshold
            if is_inactive and binding.api_client_id not in inactive_clients:
                inactive_clients.append(binding.api_client_id)

    # Fetch permission change history from audit log
    # Role changes are logged as admin_role_assigned or admin_role_revoked events
    permission_changes = await _get_permission_change_history(db)

    await db.commit()

    return AccessReviewExportResponse(
        exported_at=datetime.now(UTC),
        exported_by=str(user.principal_id),
        total_bindings=len(binding_exports),
        total_users=len(user_ids),
        total_clients=len(client_ids),
        bindings=binding_exports,
        inactive_users=inactive_users,
        inactive_clients=inactive_clients,
        permission_changes=permission_changes,
    )


# -----------------------------------------------------------------------------
# Incident Management (REQ-H04)
# -----------------------------------------------------------------------------

# In-memory incident storage (in production, this would be a database table)
# This is a stub implementation for the API structure
_incidents: dict[uuid.UUID, dict[str, Any]] = {}


@router.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create incident record",
    description="Create a new incident record for tracking and investigation.",
)
async def create_incident(
    request_body: CreateIncidentRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> IncidentResponse:
    """Create a new incident record.

    Creates an incident for tracking security events, outages,
    or compliance issues. All incidents are logged to the audit trail.

    Args:
        request_body: Incident details.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Created incident record.
    """
    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)

    incident_id = uuid.uuid4()
    created_at = datetime.now(UTC)

    await security_logger.log_admin_action(
        actor=actor,
        action="create_incident",
        target_type="incident",
        target_id=str(incident_id),
        details={
            "title": request_body.title,
            "severity": request_body.severity,
            "category": request_body.category,
        },
    )

    # Store incident (in production, this would be a database insert)
    incident_data = {
        "incident_id": incident_id,
        "title": request_body.title,
        "severity": request_body.severity,
        "category": request_body.category,
        "status": "open",
        "description": request_body.description,
        "detected_at": request_body.detected_at,
        "created_at": created_at,
        "created_by": str(user.principal_id),
        "affected_deliveries": request_body.affected_deliveries or [],
        "resolved_at": None,
        "timeline_events": [
            {
                "timestamp": created_at,
                "event_type": "incident_created",
                "actor": str(user.principal_id),
                "description": "Incident record created",
                "metadata": {"initial_assessment": request_body.initial_assessment},
            }
        ],
    }
    _incidents[incident_id] = incident_data

    await db.commit()

    logger.warning(
        "Incident created: %s (severity: %s)",
        request_body.title,
        request_body.severity,
        extra={
            "incident_id": str(incident_id),
            "severity": request_body.severity,
            "category": request_body.category,
        },
    )

    return IncidentResponse(
        incident_id=incident_id,
        title=request_body.title,
        severity=request_body.severity,
        category=request_body.category,
        status="open",
        description=request_body.description,
        detected_at=request_body.detected_at,
        created_at=created_at,
        created_by=str(user.principal_id),
        affected_deliveries=request_body.affected_deliveries or [],
        resolved_at=None,
    )


@router.get(
    "/incidents/{incident_id}/export",
    response_model=IncidentExportResponse,
    summary="Export incident timeline",
    description="Export complete incident timeline bundle for review or compliance.",
)
async def export_incident(
    incident_id: uuid.UUID,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> IncidentExportResponse:
    """Export incident timeline bundle.

    Generates a comprehensive export of the incident including
    timeline events and affected delivery summaries.

    Args:
        incident_id: UUID of the incident.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Incident export with timeline and affected deliveries.

    Raises:
        HTTPException: If incident not found.
    """
    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_sensitive_access(
        actor=actor,
        resource_type="incident",
        resource_id=str(incident_id),
        access_type="export",
        purpose="incident_review",
    )

    # Get incident (in production, this would be a database query)
    incident_data = _incidents.get(incident_id)
    if not incident_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found",
        )

    # Get affected delivery summaries
    affected_summaries: list[DeliveryIncidentSummary] = []
    if incident_data.get("affected_deliveries"):
        for del_id in incident_data["affected_deliveries"]:
            delivery_query = select(Delivery).where(Delivery.delivery_id == del_id)
            result = await db.execute(delivery_query)
            delivery = result.scalar_one_or_none()
            if delivery:
                affected_summaries.append(
                    DeliveryIncidentSummary(
                        delivery_id=delivery.delivery_id,
                        state=delivery.state.value,
                        sender_party_id=delivery.sender_party_id,
                        recipient_party_id=delivery.recipient_party_id,
                        created_at=delivery.created_at,
                    )
                )

    # Build timeline events
    timeline_events = [
        IncidentTimelineEvent(
            timestamp=e["timestamp"],
            event_type=e["event_type"],
            actor=e["actor"],
            description=e["description"],
            metadata=e.get("metadata"),
        )
        for e in incident_data.get("timeline_events", [])
    ]

    # Compute export hash
    export_data = {
        "incident_id": str(incident_id),
        "title": incident_data["title"],
        "exported_at": datetime.now(UTC).isoformat(),
        "exported_by": str(user.principal_id),
    }
    export_hash = hashlib.sha256(json.dumps(export_data, sort_keys=True).encode()).hexdigest()

    await db.commit()

    return IncidentExportResponse(
        incident_id=incident_id,
        title=incident_data["title"],
        severity=incident_data["severity"],
        category=incident_data["category"],
        status=incident_data["status"],
        description=incident_data["description"],
        detected_at=incident_data["detected_at"],
        created_at=incident_data["created_at"],
        created_by=incident_data["created_by"],
        resolved_at=incident_data.get("resolved_at"),
        affected_deliveries=affected_summaries,
        timeline_events=timeline_events,
        exported_at=datetime.now(UTC),
        exported_by=str(user.principal_id),
        export_hash=export_hash,
    )


# -----------------------------------------------------------------------------
# System Statistics
# -----------------------------------------------------------------------------


@router.get(
    "/stats",
    response_model=SystemStatsResponse,
    summary="Get system statistics",
    description="Get comprehensive system statistics for monitoring and reporting.",
)
async def get_system_stats(
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> SystemStatsResponse:
    """Get comprehensive system statistics.

    Provides statistics on deliveries, evidence, users, and storage
    for monitoring and reporting purposes.

    Args:
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        System statistics across all subsystems.
    """
    from qerds.db.models.auth import AdminUser as AdminUserModel
    from qerds.db.models.auth import ApiClient
    from qerds.db.models.parties import Party

    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="view_system_stats",
        target_type="system",
        target_id="stats",
    )

    now = datetime.now(UTC)
    today_start = datetime.combine(now.date(), datetime.min.time(), tzinfo=UTC)
    week_start = today_start - timedelta(days=7)
    month_start = today_start - timedelta(days=30)

    # Delivery statistics
    total_deliveries = (await db.execute(select(func.count()).select_from(Delivery))).scalar_one()

    # Count by state
    state_counts_query = select(Delivery.state, func.count(Delivery.delivery_id)).group_by(
        Delivery.state
    )
    state_results = await db.execute(state_counts_query)
    by_state = {row[0].value: row[1] for row in state_results.all()}

    # Count by jurisdiction
    jurisdiction_counts_query = select(
        Delivery.jurisdiction_profile, func.count(Delivery.delivery_id)
    ).group_by(Delivery.jurisdiction_profile)
    jurisdiction_results = await db.execute(jurisdiction_counts_query)
    by_jurisdiction = {row[0]: row[1] for row in jurisdiction_results.all()}

    # Time-based counts
    created_today = (
        await db.execute(
            select(func.count()).select_from(Delivery).where(Delivery.created_at >= today_start)
        )
    ).scalar_one()

    created_this_week = (
        await db.execute(
            select(func.count()).select_from(Delivery).where(Delivery.created_at >= week_start)
        )
    ).scalar_one()

    created_this_month = (
        await db.execute(
            select(func.count()).select_from(Delivery).where(Delivery.created_at >= month_start)
        )
    ).scalar_one()

    # Evidence statistics
    total_evidence_events = (
        await db.execute(select(func.count()).select_from(EvidenceEvent))
    ).scalar_one()

    total_evidence_objects = (
        await db.execute(select(func.count()).select_from(EvidenceObject))
    ).scalar_one()

    qualified_count = (
        await db.execute(
            select(func.count())
            .select_from(EvidenceObject)
            .where(EvidenceObject.qualification_label == QualificationLabel.QUALIFIED)
        )
    ).scalar_one()

    non_qualified_count = (
        await db.execute(
            select(func.count())
            .select_from(EvidenceObject)
            .where(EvidenceObject.qualification_label == QualificationLabel.NON_QUALIFIED)
        )
    ).scalar_one()

    event_type_counts_query = select(
        EvidenceEvent.event_type, func.count(EvidenceEvent.event_id)
    ).group_by(EvidenceEvent.event_type)
    event_type_results = await db.execute(event_type_counts_query)
    by_event_type = {row[0].value: row[1] for row in event_type_results.all()}

    # User statistics
    total_admin_users = (
        await db.execute(select(func.count()).select_from(AdminUserModel))
    ).scalar_one()

    active_admin_users = (
        await db.execute(
            select(func.count())
            .select_from(AdminUserModel)
            .where(AdminUserModel.is_active.is_(True))
        )
    ).scalar_one()

    total_api_clients = (await db.execute(select(func.count()).select_from(ApiClient))).scalar_one()

    active_api_clients = (
        await db.execute(
            select(func.count()).select_from(ApiClient).where(ApiClient.is_active.is_(True))
        )
    ).scalar_one()

    total_parties = (await db.execute(select(func.count()).select_from(Party))).scalar_one()

    # Storage statistics
    total_content_objects = (
        await db.execute(select(func.count()).select_from(ContentObject))
    ).scalar_one()

    total_content_size = (
        await db.execute(select(func.coalesce(func.sum(ContentObject.size_bytes), 0)))
    ).scalar_one()

    # Audit log record count
    from qerds.db.models.audit import AuditLogRecord

    audit_log_count = (
        await db.execute(select(func.count()).select_from(AuditLogRecord))
    ).scalar_one()

    await db.commit()

    return SystemStatsResponse(
        generated_at=now,
        delivery_stats=DeliveryStats(
            total_deliveries=total_deliveries,
            by_state=by_state,
            by_jurisdiction=by_jurisdiction,
            created_today=created_today,
            created_this_week=created_this_week,
            created_this_month=created_this_month,
            average_time_to_accept_hours=None,  # Would require more complex query
        ),
        evidence_stats=EvidenceStats(
            total_evidence_events=total_evidence_events,
            total_evidence_objects=total_evidence_objects,
            qualified_count=qualified_count,
            non_qualified_count=non_qualified_count,
            by_event_type=by_event_type,
        ),
        user_stats=UserStats(
            total_admin_users=total_admin_users,
            active_admin_users=active_admin_users,
            total_api_clients=total_api_clients,
            active_api_clients=active_api_clients,
            total_parties=total_parties,
        ),
        storage_stats=StorageStats(
            total_content_objects=total_content_objects,
            total_content_size_bytes=total_content_size,
            total_evidence_blobs=total_evidence_objects,  # Approximation
            audit_log_record_count=audit_log_count,
        ),
    )


# -----------------------------------------------------------------------------
# Conformity Assessment Packages (REQ-A02)
# -----------------------------------------------------------------------------


async def get_conformity_package_service(db: DbSession) -> ConformityPackageService:
    """Get the conformity package service with required dependencies.

    Initializes the trust service and object store for package generation.

    Returns:
        Configured ConformityPackageService instance.
    """
    from pathlib import Path

    from qerds.core.settings import get_settings
    from qerds.services.conformity_package import ConformityPackageService
    from qerds.services.storage import ObjectStoreClient
    from qerds.services.trust import QualificationMode, TrustService, TrustServiceConfig

    settings = get_settings()

    # Initialize trust service
    trust_config = TrustServiceConfig(
        mode=QualificationMode(settings.claim_state.value),
        key_storage_path=Path(settings.trust.key_storage_path),
    )
    trust_service = TrustService(trust_config)
    await trust_service.initialize()

    # Initialize object store
    object_store = ObjectStoreClient.from_settings(settings.s3)

    # Use project root as base path for policy files
    base_path = Path(__file__).parent.parent.parent.parent.parent

    return ConformityPackageService(db, trust_service, object_store, base_path=base_path)


@router.post(
    "/conformity-packages",
    response_model=ConformityPackageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate conformity assessment package",
    description="Generate a comprehensive package for QERDS/LRE conformity assessment.",
)
async def generate_conformity_package(
    request_body: ConformityPackageRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> ConformityPackageResponse:
    """Generate a conformity assessment readiness package.

    Creates a comprehensive package for auditors performing QERDS/LRE
    certification assessments. The package includes:

    - Requirement traceability matrix (REQ-A04)
    - Policy document references (REQ-A03)
    - Evidence samples from the system
    - Configuration snapshots
    - Key inventory and ceremony evidence (REQ-H07)
    - Release/SBOM metadata

    The package is sealed and timestamped, then stored to object storage.

    Args:
        request_body: Package generation parameters.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        ConformityPackageResponse with package details and storage reference.
    """
    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="generate_conformity_package",
        target_type="conformity_package",
        target_id=request_body.assessment_type,
        details={
            "assessment_type": request_body.assessment_type,
            "reason": request_body.reason,
            "include_evidence": request_body.include_evidence_samples,
            "include_ceremonies": request_body.include_key_ceremonies,
        },
    )

    try:
        # Get conformity package service
        conformity_service = await get_conformity_package_service(db)

        # Generate the sealed package
        sealed_package = await conformity_service.generate_conformity_package(
            assessment_type=request_body.assessment_type,
            created_by=str(user.principal_id),
            reason=request_body.reason,
            include_evidence_samples=request_body.include_evidence_samples,
            include_key_ceremonies=request_body.include_key_ceremonies,
        )

        await db.commit()

        return ConformityPackageResponse(
            package_id=sealed_package.package_id,
            assessment_type=sealed_package.assessment_type,
            created_at=sealed_package.created_at,
            created_by=sealed_package.created_by,
            requirement_count=sealed_package.contents_summary.get("requirement_count", 0),
            policy_document_count=sealed_package.contents_summary.get("policy_document_count", 0),
            evidence_sample_count=sealed_package.contents_summary.get("evidence_sample_count", 0),
            config_snapshot_count=sealed_package.contents_summary.get("config_snapshot_count", 0),
            key_count=sealed_package.contents_summary.get("key_count", 0),
            ceremony_event_count=sealed_package.contents_summary.get("ceremony_event_count", 0),
            package_hash=sealed_package.package_hash,
            storage_ref=sealed_package.storage_ref,
            qualification_label=sealed_package.qualification_label,
        )
    except Exception as e:
        logger.exception("Failed to generate conformity package: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate conformity package: {e!s}",
        ) from e


@router.get(
    "/traceability-matrix",
    response_model=TraceabilityMatrixResponse,
    summary="Get requirement traceability matrix",
    description="Export the requirement traceability matrix for REQ-A04 compliance.",
)
async def get_traceability_matrix(
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> TraceabilityMatrixResponse:
    """Get the requirement traceability matrix.

    Returns the complete traceability matrix mapping requirement IDs
    to implementation modules, tests, and evidence artifacts per REQ-A04.

    Args:
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        TraceabilityMatrixResponse with all traceability entries.
    """
    from qerds.services.conformity_package import REQUIREMENT_TRACEABILITY

    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="view_traceability_matrix",
        target_type="traceability_matrix",
        target_id="all",
    )

    # Build entries from the traceability constant
    entries = []
    by_category: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for req_id, req_data in REQUIREMENT_TRACEABILITY.items():
        # Determine implementation status
        has_modules = bool(req_data.get("modules"))
        has_tests = bool(req_data.get("tests"))

        if has_modules and has_tests:
            impl_status = "implemented"
        elif has_modules:
            impl_status = "partial"
        else:
            impl_status = "not_implemented"

        category = req_data.get("category", "other")

        # Update counts
        by_category[category] = by_category.get(category, 0) + 1
        by_status[impl_status] = by_status.get(impl_status, 0) + 1

        entries.append(
            TraceabilityEntryResponse(
                requirement_id=req_id,
                title=req_data.get("title", ""),
                category=category,
                modules=req_data.get("modules", []),
                tests=req_data.get("tests", []),
                evidence=req_data.get("evidence", []),
                implementation_status=impl_status,
            )
        )

    await db.commit()

    return TraceabilityMatrixResponse(
        generated_at=datetime.now(UTC),
        generated_by=str(user.principal_id),
        total_requirements=len(entries),
        by_category=by_category,
        by_status=by_status,
        entries=entries,
    )


# -----------------------------------------------------------------------------
# DR Evidence Management (REQ-D09, REQ-H08)
# -----------------------------------------------------------------------------

# In-memory DR evidence service instance (would be dependency injected in production)
_dr_evidence_service = None


async def get_dr_evidence_service(db: DbSession) -> DREvidenceService:
    """Get DR evidence service instance.

    Creates or returns a cached DR evidence service.
    In production, this would be properly dependency-injected.

    Args:
        db: Database session.

    Returns:
        DREvidenceService instance.
    """
    from qerds.services.dr_evidence import DREvidenceService

    global _dr_evidence_service
    if _dr_evidence_service is None:
        _dr_evidence_service = DREvidenceService(db)
    return _dr_evidence_service


@router.post(
    "/dr-evidence/backup",
    response_model=DREvidenceRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record backup execution",
    description="Record evidence of a backup execution for audit purposes.",
)
async def record_backup_execution(
    request_body: RecordBackupExecutionRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> DREvidenceRecordResponse:
    """Record a backup execution event.

    Records evidence of a backup operation for compliance with REQ-D09 and REQ-H08.
    This is used by operators to document scheduled and manual backups.

    Args:
        request_body: Backup execution details.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Created evidence record.
    """
    from qerds.services.dr_evidence import BackupScope, DREvidenceOutcome

    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="record_backup_execution",
        target_type="dr_evidence",
        target_id="backup",
        details={
            "outcome": request_body.outcome,
            "summary": request_body.summary[:100],
        },
    )

    try:
        service = await get_dr_evidence_service(db)

        # Convert schema to domain objects
        backup_scope = None
        if request_body.backup_scope:
            backup_scope = BackupScope(
                postgresql=request_body.backup_scope.postgresql,
                object_store=request_body.backup_scope.object_store,
                audit_logs=request_body.backup_scope.audit_logs,
                config=request_body.backup_scope.config,
            )

        outcome = DREvidenceOutcome(request_body.outcome)

        record = await service.record_backup_execution(
            executed_by=str(user.principal_id),
            outcome=outcome,
            backup_scope=backup_scope,
            duration_seconds=request_body.duration_seconds,
            summary=request_body.summary,
            details=request_body.details or {},
            executed_at=request_body.executed_at,
        )

        await db.commit()

        return _convert_record_to_response(record)

    except Exception as e:
        logger.exception("Failed to record backup execution: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record backup execution: {e!s}",
        ) from e


@router.post(
    "/dr-evidence/restore-test",
    response_model=DREvidenceRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record restore test",
    description="Record evidence of a restore test for audit purposes.",
)
async def record_restore_test(
    request_body: RecordRestoreTestRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> DREvidenceRecordResponse:
    """Record a restore test execution.

    Records evidence of a restore validation test for compliance with REQ-D09 and REQ-H08.

    Args:
        request_body: Restore test details.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Created evidence record.
    """
    from qerds.services.dr_evidence import BackupScope, DREvidenceOutcome

    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="record_restore_test",
        target_type="dr_evidence",
        target_id="restore_test",
        details={
            "outcome": request_body.outcome,
            "summary": request_body.summary[:100],
        },
    )

    try:
        service = await get_dr_evidence_service(db)

        # Convert schema to domain objects
        backup_scope = None
        if request_body.backup_scope:
            backup_scope = BackupScope(
                postgresql=request_body.backup_scope.postgresql,
                object_store=request_body.backup_scope.object_store,
                audit_logs=request_body.backup_scope.audit_logs,
                config=request_body.backup_scope.config,
            )

        outcome = DREvidenceOutcome(request_body.outcome)

        record = await service.record_restore_test(
            executed_by=str(user.principal_id),
            outcome=outcome,
            backup_scope=backup_scope,
            duration_seconds=request_body.duration_seconds,
            summary=request_body.summary,
            details=request_body.details or {},
            executed_at=request_body.executed_at,
        )

        await db.commit()

        return _convert_record_to_response(record)

    except Exception as e:
        logger.exception("Failed to record restore test: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record restore test: {e!s}",
        ) from e


@router.post(
    "/dr-evidence/dr-drill",
    response_model=DREvidenceRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record DR drill",
    description="Record evidence of a disaster recovery drill/exercise for audit purposes.",
)
async def record_dr_drill(
    request_body: RecordDRDrillRequest,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> DREvidenceRecordResponse:
    """Record a DR drill/exercise.

    Records evidence of a disaster recovery exercise for compliance with REQ-D09 and REQ-H08.
    This includes RPO/RTO measurements for validation against targets.

    Args:
        request_body: DR drill details including RPO/RTO measurements.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        Created evidence record.
    """
    from qerds.services.dr_evidence import DREvidenceOutcome, RPOTarget, RTOTarget

    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="record_dr_drill",
        target_type="dr_evidence",
        target_id="dr_drill",
        details={
            "outcome": request_body.outcome,
            "summary": request_body.summary[:100],
        },
    )

    try:
        service = await get_dr_evidence_service(db)

        # Convert schema to domain objects
        rpo = None
        if request_body.rpo:
            rpo = RPOTarget(
                target_minutes=request_body.rpo.target_minutes,
                measured_minutes=request_body.rpo.measured_minutes,
                meets_target=request_body.rpo.meets_target,
            )

        rto = None
        if request_body.rto:
            rto = RTOTarget(
                target_minutes=request_body.rto.target_minutes,
                measured_minutes=request_body.rto.measured_minutes,
                meets_target=request_body.rto.meets_target,
            )

        outcome = DREvidenceOutcome(request_body.outcome)

        record = await service.record_dr_drill(
            executed_by=str(user.principal_id),
            outcome=outcome,
            duration_seconds=request_body.duration_seconds,
            rpo=rpo,
            rto=rto,
            summary=request_body.summary,
            details=request_body.details or {},
            executed_at=request_body.executed_at,
        )

        await db.commit()

        return _convert_record_to_response(record)

    except Exception as e:
        logger.exception("Failed to record DR drill: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record DR drill: {e!s}",
        ) from e


@router.get(
    "/dr-evidence",
    response_model=DREvidenceListResponse,
    summary="List DR evidence records",
    description="List DR evidence records with optional filtering.",
)
async def list_dr_evidence(
    user: AdminUser,
    db: DbSession,
    request: Request,
    evidence_type: Annotated[
        str | None,
        Query(
            pattern=r"^(backup_execution|restore_test|dr_drill|rto_measurement|rpo_measurement)$",
            description="Filter by evidence type",
        ),
    ] = None,
    start_date: Annotated[
        datetime | None, Query(description="Filter by executed_at >= start_date")
    ] = None,
    end_date: Annotated[
        datetime | None, Query(description="Filter by executed_at <= end_date")
    ] = None,
    limit: Annotated[
        int, Query(ge=1, le=1000, description="Maximum number of records to return")
    ] = 100,
) -> DREvidenceListResponse:
    """List DR evidence records with optional filtering.

    Args:
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.
        evidence_type: Optional filter by evidence type.
        start_date: Optional filter by start date.
        end_date: Optional filter by end date.
        limit: Maximum records to return.

    Returns:
        List of matching evidence records.
    """
    from qerds.services.dr_evidence import DREvidenceType

    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="list_dr_evidence",
        target_type="dr_evidence",
        target_id="list",
        details={
            "evidence_type": evidence_type,
            "start_date": start_date.isoformat() if start_date else None,
            "end_date": end_date.isoformat() if end_date else None,
        },
    )

    try:
        service = await get_dr_evidence_service(db)

        # Convert evidence_type string to enum
        type_filter = None
        if evidence_type:
            type_filter = DREvidenceType(evidence_type)

        records = await service.list_records(
            evidence_type=type_filter,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )

        await db.commit()

        return DREvidenceListResponse(
            records=[_convert_record_to_response(r) for r in records],
            total_count=len(records),
        )

    except Exception as e:
        logger.exception("Failed to list DR evidence: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list DR evidence: {e!s}",
        ) from e


@router.get(
    "/dr-evidence/summary",
    response_model=DREvidenceSummaryResponse,
    summary="Get DR evidence summary",
    description="Get summary statistics for DR evidence in a time period.",
)
async def get_dr_evidence_summary(
    user: AdminUser,
    db: DbSession,
    request: Request,
    start_date: Annotated[datetime, Query(description="Start of the summary period")],
    end_date: Annotated[datetime, Query(description="End of the summary period")],
) -> DREvidenceSummaryResponse:
    """Get DR evidence summary for a time period.

    Provides summary statistics including backup counts, restore test counts,
    DR drill counts, success rates, and RPO/RTO compliance status.

    Args:
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.
        start_date: Start of the summary period.
        end_date: End of the summary period.

    Returns:
        Summary statistics for the period.
    """
    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="get_dr_evidence_summary",
        target_type="dr_evidence",
        target_id="summary",
        details={
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
        },
    )

    try:
        service = await get_dr_evidence_service(db)

        summary = await service.get_summary(start_date, end_date)

        await db.commit()

        return DREvidenceSummaryResponse(
            period_start=summary.period_start,
            period_end=summary.period_end,
            backup_count=summary.backup_count,
            restore_test_count=summary.restore_test_count,
            dr_drill_count=summary.dr_drill_count,
            success_rate=summary.success_rate,
            last_successful_backup=summary.last_successful_backup,
            last_restore_test=summary.last_restore_test,
            last_dr_drill=summary.last_dr_drill,
            rpo_compliance=summary.rpo_compliance,
            rto_compliance=summary.rto_compliance,
        )

    except Exception as e:
        logger.exception("Failed to get DR evidence summary: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get DR evidence summary: {e!s}",
        ) from e


@router.get(
    "/dr-evidence/{record_id}",
    response_model=DREvidenceRecordResponse,
    summary="Get DR evidence record",
    description="Get a specific DR evidence record by ID.",
)
async def get_dr_evidence_record(
    record_id: uuid.UUID,
    user: AdminUser,
    db: DbSession,
    request: Request,
) -> DREvidenceRecordResponse:
    """Get a specific DR evidence record.

    Args:
        record_id: UUID of the evidence record.
        user: Authenticated admin user.
        db: Database session.
        request: HTTP request for audit logging.

    Returns:
        The evidence record.

    Raises:
        HTTPException: If record not found.
    """
    from qerds.services.dr_evidence import DREvidenceNotFoundError

    # Log the admin action
    security_logger = SecurityEventLogger(db)
    actor = _get_security_actor(user, request)
    await security_logger.log_admin_action(
        actor=actor,
        action="get_dr_evidence_record",
        target_type="dr_evidence",
        target_id=str(record_id),
    )

    try:
        service = await get_dr_evidence_service(db)

        record = await service.get_record(record_id)

        await db.commit()

        return _convert_record_to_response(record)

    except DREvidenceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DR evidence record {record_id} not found",
        ) from e
    except Exception as e:
        logger.exception("Failed to get DR evidence record: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get DR evidence record: {e!s}",
        ) from e


def _convert_record_to_response(record: DREvidenceRecord) -> DREvidenceRecordResponse:
    """Convert a DREvidenceRecord to API response schema.

    Args:
        record: The DREvidenceRecord from the service.

    Returns:
        API response schema.
    """
    backup_scope = None
    if record.backup_scope:
        backup_scope = BackupScopeSchema(
            postgresql=record.backup_scope.postgresql,
            object_store=record.backup_scope.object_store,
            audit_logs=record.backup_scope.audit_logs,
            config=record.backup_scope.config,
        )

    rpo = None
    if record.rpo:
        rpo = RPOTargetSchema(
            target_minutes=record.rpo.target_minutes,
            measured_minutes=record.rpo.measured_minutes,
            meets_target=record.rpo.meets_target,
        )

    rto = None
    if record.rto:
        rto = RTOTargetSchema(
            target_minutes=record.rto.target_minutes,
            measured_minutes=record.rto.measured_minutes,
            meets_target=record.rto.meets_target,
        )

    return DREvidenceRecordResponse(
        record_id=record.record_id,
        evidence_type=record.evidence_type.value,
        outcome=record.outcome.value,
        executed_at=record.executed_at,
        executed_by=record.executed_by,
        duration_seconds=record.duration_seconds,
        backup_scope=backup_scope,
        rpo=rpo,
        rto=rto,
        summary=record.summary,
        details=record.details,
        artifact_refs=record.artifact_refs,
        record_hash=record.record_hash,
        created_at=record.created_at,
    )
