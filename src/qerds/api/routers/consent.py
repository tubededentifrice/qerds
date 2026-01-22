"""Consent management API router.

Handles recipient consent operations for LRE compliance (REQ-F06).
All endpoints require recipient authentication.

CPCE Compliance (Critical):
- Consent required before first LRE can be sent to consumer
- Consent can be withdrawn at any time
- Full audit trail maintained for all consent actions
- Evidence exportable for compliance verification
"""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from qerds.api.middleware.auth import AuthenticatedUser, require_authenticated_user
from qerds.api.schemas.consent import (
    ConsentDetail,
    ConsentErrorResponse,
    ConsentEvidenceResponse,
    ConsentListResponse,
    ConsentStatusResponse,
    ConsentSummary,
    GrantConsentRequest,
    GrantConsentResponse,
    WithdrawConsentRequest,
    WithdrawConsentResponse,
)
from qerds.db.models.base import ConsentState, ConsentType
from qerds.services.consent import (
    ConsentAlreadyGrantedError,
    ConsentNotFoundError,
    ConsentService,
    InvalidConsentStateError,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/consent",
    tags=["consent"],
    responses={
        401: {"description": "Authentication required", "model": ConsentErrorResponse},
        403: {"description": "Insufficient permissions", "model": ConsentErrorResponse},
    },
)


# ---------------------------------------------------------------------------
# Database session dependency
# ---------------------------------------------------------------------------


async def get_db_session() -> AsyncSession:
    """Get database session.

    Uses the application's async session factory.
    """
    from qerds.db import get_async_session

    async with get_async_session() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db_session)]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _consent_type_from_string(consent_type_str: str) -> ConsentType:
    """Convert consent type string to enum.

    Args:
        consent_type_str: String value of consent type.

    Returns:
        ConsentType enum value.

    Raises:
        HTTPException: If consent type is invalid.
    """
    try:
        return ConsentType(consent_type_str)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_consent_type",
                "message": f"Invalid consent type: {consent_type_str}",
                "valid_types": [ct.value for ct in ConsentType],
            },
        ) from e


def _get_client_ip(request: Request, x_forwarded_for: str | None = None) -> str | None:
    """Extract client IP address from request.

    Handles X-Forwarded-For header for proxied requests.

    Args:
        request: FastAPI request object.
        x_forwarded_for: X-Forwarded-For header value.

    Returns:
        Client IP address or None.
    """
    if x_forwarded_for:
        # Take the first IP in the chain (original client)
        return x_forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for consent namespace.

    Returns:
        Health status for the consent API subsystem.
    """
    return {"status": "healthy", "namespace": "consent"}


# ---------------------------------------------------------------------------
# Consent status and listing
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=ConsentStatusResponse,
    summary="Check consent status",
    description="""
    Check the current consent status for the authenticated recipient.

    Returns the consent state (pending, granted, withdrawn) and
    whether consent is currently valid for receiving LRE.
    """,
)
async def get_consent_status(
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    db: DbSession,
    consent_type: str = "fr_lre_electronic_delivery",
) -> ConsentStatusResponse:
    """Get consent status for the authenticated recipient.

    Args:
        user: Authenticated user.
        db: Database session.
        consent_type: Type of consent to check.

    Returns:
        Current consent status.
    """
    consent_type_enum = _consent_type_from_string(consent_type)
    service = ConsentService(db)

    state = await service.get_consent_state(user.principal_id, consent_type_enum)
    has_valid = state == ConsentState.GRANTED

    # Get consented_at if available
    consented_at = None
    if has_valid:
        consent = await service.get_consent(user.principal_id, consent_type_enum)
        if consent:
            consented_at = consent.consented_at

    logger.info(
        "Consent status checked",
        extra={
            "recipient_party_id": str(user.principal_id),
            "consent_type": consent_type,
            "state": state.value,
        },
    )

    return ConsentStatusResponse(
        recipient_party_id=user.principal_id,
        consent_type=consent_type,
        state=state.value,
        has_valid_consent=has_valid,
        consented_at=consented_at,
    )


@router.get(
    "/list",
    response_model=ConsentListResponse,
    summary="List all consents",
    description="""
    List all consent records for the authenticated recipient.

    Returns all consent types with their current states.
    """,
)
async def list_consents(
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    db: DbSession,
) -> ConsentListResponse:
    """List all consent records for the authenticated recipient.

    Args:
        user: Authenticated user.
        db: Database session.

    Returns:
        List of all consent records.
    """
    service = ConsentService(db)
    records = await service.list_consents_for_party(user.principal_id)

    consents = [
        ConsentSummary(
            consent_id=r.consent_id,
            consent_type=r.consent_type.value,
            state=r.state.value,
            consented_at=r.consented_at,
            withdrawn_at=r.withdrawn_at,
        )
        for r in records
    ]

    logger.info(
        "Consents listed",
        extra={
            "recipient_party_id": str(user.principal_id),
            "count": len(consents),
        },
    )

    return ConsentListResponse(
        recipient_party_id=user.principal_id,
        consents=consents,
        total=len(consents),
    )


@router.get(
    "/{consent_type}",
    response_model=ConsentDetail,
    responses={
        404: {"description": "Consent not found", "model": ConsentErrorResponse},
    },
    summary="Get consent details",
    description="""
    Get detailed information about a specific consent record.

    Includes full audit information for compliance purposes.
    """,
)
async def get_consent_detail(
    consent_type: str,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    db: DbSession,
) -> ConsentDetail:
    """Get detailed consent information.

    Args:
        consent_type: Type of consent to retrieve.
        user: Authenticated user.
        db: Database session.

    Returns:
        Full consent details.

    Raises:
        HTTPException: If consent not found.
    """
    consent_type_enum = _consent_type_from_string(consent_type)
    service = ConsentService(db)

    try:
        record = await service.get_consent_record(user.principal_id, consent_type_enum)
    except ConsentNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "consent_not_found",
                "message": str(e),
                "consent_type": consent_type,
            },
        ) from e

    return ConsentDetail(
        consent_id=record.consent_id,
        recipient_party_id=record.recipient_party_id,
        consent_type=record.consent_type.value,
        state=record.state.value,
        consented_at=record.consented_at,
        consented_by=record.consented_by,
        withdrawn_at=record.withdrawn_at,
        withdrawal_reason=None,  # Not in ConsentRecord, would need to fetch from DB
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


# ---------------------------------------------------------------------------
# Grant consent
# ---------------------------------------------------------------------------


@router.post(
    "/grant",
    response_model=GrantConsentResponse,
    responses={
        400: {"description": "Consent already granted", "model": ConsentErrorResponse},
    },
    summary="Grant consent",
    description="""
    Grant consent for receiving electronic registered delivery (LRE).

    **CPCE Compliance (REQ-F06)**: This action records the recipient's
    explicit consent to receive LRE electronically. The consent is
    recorded with full audit trail including timestamp, IP address,
    and user agent.

    Requirements:
    - Recipient must acknowledge the consent text
    - A hash of the consent text shown should be provided for audit

    After granting consent:
    - Recipient can receive LRE deliveries
    - Consent evidence is stored for compliance
    """,
)
async def grant_consent(
    request_body: GrantConsentRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    db: DbSession,
    user_agent: Annotated[str | None, Header(alias="User-Agent")] = None,
    x_forwarded_for: Annotated[str | None, Header(alias="X-Forwarded-For")] = None,
) -> GrantConsentResponse:
    """Grant consent for electronic delivery.

    Args:
        request_body: Grant consent request with acknowledgment.
        request: FastAPI request for IP extraction.
        user: Authenticated user.
        db: Database session.
        user_agent: User agent header.
        x_forwarded_for: X-Forwarded-For header for proxy support.

    Returns:
        Confirmation of consent grant.

    Raises:
        HTTPException: If consent acknowledgment not provided or already granted.
    """
    if not request_body.acknowledge_consent_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "acknowledgment_required",
                "message": "You must acknowledge the consent text to grant consent",
            },
        )

    consent_type_enum = _consent_type_from_string(request_body.consent_type)
    client_ip = _get_client_ip(request, x_forwarded_for)
    service = ConsentService(db)

    try:
        consent = await service.grant_consent(
            recipient_party_id=user.principal_id,
            consent_type=consent_type_enum,
            consented_by=user.principal_id,
            ip_address=client_ip,
            user_agent=user_agent,
            consent_text_hash=request_body.consent_text_hash,
            metadata=request_body.metadata,
        )
        await db.commit()

    except ConsentAlreadyGrantedError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "consent_already_granted",
                "message": str(e),
                "consent_type": request_body.consent_type,
            },
        ) from e

    logger.info(
        "Consent granted via API",
        extra={
            "consent_id": str(consent.consent_id),
            "recipient_party_id": str(user.principal_id),
            "consent_type": request_body.consent_type,
            "ip_address": client_ip,
        },
    )

    return GrantConsentResponse(
        consent_id=consent.consent_id,
        consent_type=request_body.consent_type,
        state=consent.state.value,
        consented_at=consent.consented_at,
    )


# ---------------------------------------------------------------------------
# Withdraw consent
# ---------------------------------------------------------------------------


@router.post(
    "/withdraw",
    response_model=WithdrawConsentResponse,
    responses={
        400: {"description": "Invalid consent state", "model": ConsentErrorResponse},
        404: {"description": "Consent not found", "model": ConsentErrorResponse},
    },
    summary="Withdraw consent",
    description="""
    Withdraw consent for receiving electronic registered delivery (LRE).

    **CPCE Compliance (REQ-F06)**: Recipients can withdraw their consent
    at any time. The withdrawal is recorded with full audit trail.

    After withdrawing consent:
    - No new LRE deliveries can be sent to the recipient
    - Existing deliveries in progress may still be completed
    - The withdrawal is recorded for compliance audit
    """,
)
async def withdraw_consent(
    request_body: WithdrawConsentRequest,
    request: Request,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    db: DbSession,
    user_agent: Annotated[str | None, Header(alias="User-Agent")] = None,
    x_forwarded_for: Annotated[str | None, Header(alias="X-Forwarded-For")] = None,
) -> WithdrawConsentResponse:
    """Withdraw consent for electronic delivery.

    Args:
        request_body: Withdraw consent request with optional reason.
        request: FastAPI request for IP extraction.
        user: Authenticated user.
        db: Database session.
        user_agent: User agent header.
        x_forwarded_for: X-Forwarded-For header for proxy support.

    Returns:
        Confirmation of consent withdrawal.

    Raises:
        HTTPException: If consent not found or not in granted state.
    """
    consent_type_enum = _consent_type_from_string(request_body.consent_type)
    client_ip = _get_client_ip(request, x_forwarded_for)
    service = ConsentService(db)

    try:
        consent = await service.withdraw_consent(
            recipient_party_id=user.principal_id,
            consent_type=consent_type_enum,
            reason=request_body.reason,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        await db.commit()

    except ConsentNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "consent_not_found",
                "message": str(e),
                "consent_type": request_body.consent_type,
            },
        ) from e
    except InvalidConsentStateError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_consent_state",
                "message": str(e),
                "consent_type": request_body.consent_type,
                "current_state": e.current_state.value,
            },
        ) from e

    logger.info(
        "Consent withdrawn via API",
        extra={
            "consent_id": str(consent.consent_id),
            "recipient_party_id": str(user.principal_id),
            "consent_type": request_body.consent_type,
            "reason": request_body.reason,
            "ip_address": client_ip,
        },
    )

    return WithdrawConsentResponse(
        consent_id=consent.consent_id,
        consent_type=request_body.consent_type,
        state=consent.state.value,
        withdrawn_at=consent.withdrawn_at,
    )


# ---------------------------------------------------------------------------
# Evidence export
# ---------------------------------------------------------------------------


@router.get(
    "/{consent_type}/evidence",
    response_model=ConsentEvidenceResponse,
    responses={
        404: {"description": "Consent not found", "model": ConsentErrorResponse},
    },
    summary="Export consent evidence",
    description="""
    Export the full consent evidence bundle for compliance/audit.

    Returns a complete audit trail including:
    - Grant evidence (timestamp, IP, user agent, consent text hash)
    - Withdrawal evidence (if applicable)
    - All relevant metadata

    This endpoint is intended for compliance audits and legal proceedings.
    """,
)
async def export_consent_evidence(
    consent_type: str,
    user: Annotated[AuthenticatedUser, Depends(require_authenticated_user)],
    db: DbSession,
) -> ConsentEvidenceResponse:
    """Export consent evidence for compliance.

    Args:
        consent_type: Type of consent to export.
        user: Authenticated user.
        db: Database session.

    Returns:
        Full consent evidence bundle.

    Raises:
        HTTPException: If consent not found.
    """
    consent_type_enum = _consent_type_from_string(consent_type)
    service = ConsentService(db)

    try:
        evidence = await service.export_consent_evidence(
            recipient_party_id=user.principal_id,
            consent_type=consent_type_enum,
        )
    except ConsentNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "consent_not_found",
                "message": str(e),
                "consent_type": consent_type,
            },
        ) from e

    logger.info(
        "Consent evidence exported",
        extra={
            "consent_id": evidence["consent_id"],
            "recipient_party_id": str(user.principal_id),
            "consent_type": consent_type,
        },
    )

    return ConsentEvidenceResponse(
        consent_id=UUID(evidence["consent_id"]),
        recipient_party_id=UUID(evidence["recipient_party_id"]),
        consent_type=evidence["consent_type"],
        state=evidence["state"],
        created_at=evidence["created_at"],
        updated_at=evidence["updated_at"],
        grant_evidence=evidence["grant_evidence"],
        withdrawal_evidence=evidence["withdrawal_evidence"],
    )
