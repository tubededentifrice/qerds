"""Trust service API router.

Internal API endpoints for signing, sealing, and timestamping.
Per specs/implementation/45-trust-services.md, all calls must be
authenticated via mTLS in production.

Covers: REQ-C02, REQ-C03, REQ-D08, REQ-G02, REQ-H01, REQ-H07

IMPORTANT: This API is internal only and should NOT be exposed to the internet.
In production, access should be restricted via mTLS and network segmentation.
"""

from __future__ import annotations

import base64
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, Field

from qerds.services.trust import (
    KeyNotFoundError,
    QualificationMode,
    QualifiedModeNotImplementedError,
    TrustService,
    TrustServiceConfig,
    TrustServiceError,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/trust",
    tags=["trust"],
    responses={
        401: {"description": "Unauthorized - mTLS required"},
        500: {"description": "Trust service error"},
        501: {"description": "Qualified mode not implemented"},
    },
)

# Module-level service instance (initialized on startup)
_trust_service: TrustService | None = None


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------


class SealRequest(BaseModel):
    """Request to seal data with provider attestation."""

    data: str = Field(
        description="Base64-encoded data to seal",
        examples=["SGVsbG8gV29ybGQ="],
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional metadata to associate with the seal",
    )


class SealResponse(BaseModel):
    """Response containing sealed data and verification bundle."""

    seal_id: str = Field(description="Unique identifier for this seal")
    signature: str = Field(description="Base64-encoded signature")
    algorithm_suite: dict[str, Any] = Field(description="Algorithm suite used")
    key_id: str = Field(description="ID of the signing key")
    certificate_chain: list[str] = Field(description="PEM-encoded certificate chain")
    sealed_at: str = Field(description="ISO 8601 timestamp of sealing")
    content_hash: str = Field(description="SHA-384 hash of sealed content")
    qualification_label: str = Field(
        description="Qualification status (non_qualified or qualified)"
    )
    policy_snapshot_id: str = Field(description="Policy snapshot reference")


class TimestampRequest(BaseModel):
    """Request to create a timestamp token."""

    data: str = Field(
        description="Base64-encoded data to timestamp",
        examples=["SGVsbG8gV29ybGQ="],
    )
    hash_algorithm: str = Field(
        default="sha384",
        description="Hash algorithm for message imprint",
        pattern="^(sha256|sha384|sha512)$",
    )


class TimestampResponse(BaseModel):
    """Response containing timestamp token."""

    token_id: str = Field(description="Unique identifier for this timestamp")
    timestamp: str = Field(description="ISO 8601 attested timestamp")
    message_imprint: str = Field(description="Hash of timestamped data")
    hash_algorithm: str = Field(description="Hash algorithm used")
    serial_number: int = Field(description="Unique serial number")
    tsa_name: str = Field(description="Timestamp authority name")
    signature: str = Field(description="Base64-encoded timestamp signature")
    policy_oid: str = Field(description="Timestamp policy OID")
    qualification_label: str = Field(description="Qualification status")
    accuracy_seconds: int = Field(description="Timestamp accuracy in seconds")


class CheckpointRequest(BaseModel):
    """Request to create a sealed audit log checkpoint."""

    audit_log_hash: str = Field(
        description="Hash of audit log at checkpoint",
        min_length=64,
        max_length=128,
    )
    stream: str = Field(
        description="Audit stream name",
        examples=["SECURITY", "EVIDENCE", "OPS"],
    )
    sequence_number: int = Field(
        description="Latest sequence number in stream",
        ge=0,
    )


class CheckpointResponse(BaseModel):
    """Response containing sealed checkpoint."""

    checkpoint_id: str = Field(description="Unique checkpoint identifier")
    audit_log_hash: str = Field(description="Hash of audit log")
    stream: str = Field(description="Audit stream name")
    sequence_number: int = Field(description="Sequence number at checkpoint")
    seal: SealResponse = Field(description="Seal over checkpoint data")
    timestamp: TimestampResponse = Field(description="Timestamp of checkpoint")


class KeyInfoResponse(BaseModel):
    """Public information about a cryptographic key."""

    key_id: str = Field(description="Unique key identifier")
    purpose: str = Field(description="Key purpose (signing, timestamping)")
    algorithm: dict[str, Any] = Field(description="Algorithm suite")
    status: str = Field(description="Key lifecycle status")
    created_at: str = Field(description="ISO 8601 creation timestamp")
    expires_at: str | None = Field(description="ISO 8601 expiration timestamp")
    certificate_pem: str = Field(description="PEM-encoded public certificate")
    qualification_mode: str = Field(description="Qualification status")


class KeyInventoryResponse(BaseModel):
    """Response containing all key information."""

    keys: list[KeyInfoResponse] = Field(description="List of managed keys")
    mode: str = Field(description="Service qualification mode")


class RotationRequest(BaseModel):
    """Request to rotate a key (requires dual-control in production)."""

    reason: str = Field(
        description="Reason for key rotation",
        min_length=10,
        max_length=500,
    )
    approved_by: str | None = Field(
        default=None,
        description="Second approver ID (dual-control)",
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(description="Service health status")
    mode: str = Field(description="Qualification mode")
    initialized: bool = Field(description="Whether service is initialized")
    key_count: int = Field(description="Number of managed keys")


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str = Field(description="Error type")
    message: str = Field(description="Error description")
    detail: str | None = Field(default=None, description="Additional details")


# ---------------------------------------------------------------------------
# Dependency injection
# ---------------------------------------------------------------------------


async def get_trust_service() -> TrustService:
    """Get the trust service instance.

    Returns:
        Initialized TrustService.

    Raises:
        HTTPException: If service not initialized.
    """
    if _trust_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trust service not initialized",
        )
    return _trust_service


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Trust service health check",
)
async def health_check() -> HealthResponse:
    """Check trust service health.

    Returns current service status and configuration.
    """
    if _trust_service is None:
        return HealthResponse(
            status="unavailable",
            mode="unknown",
            initialized=False,
            key_count=0,
        )

    return HealthResponse(
        status="healthy",
        mode=_trust_service.mode.value,
        initialized=True,
        key_count=len(await _trust_service.get_keys()),
    )


@router.post(
    "/seal",
    response_model=SealResponse,
    summary="Seal data with provider attestation",
    responses={
        200: {"description": "Data sealed successfully"},
        400: {"description": "Invalid input data"},
    },
)
async def seal_data(
    request: SealRequest,
    service: Annotated[TrustService, Depends(get_trust_service)],
) -> SealResponse:
    """Seal canonical bytes with CMS/PKCS#7 signature.

    Creates a provider attestation over the provided data per REQ-C02.
    Returns a verification bundle containing signature, certificates,
    and algorithm information.

    The qualification_label in the response indicates whether this
    is a qualified or non-qualified seal per REQ-G02.
    """
    try:
        # Decode base64 input
        try:
            data = base64.b64decode(request.data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 encoding in data field",
            ) from e

        # Seal the data
        sealed = await service.seal(data, metadata=request.metadata)

        logger.info(
            "Sealed data: seal_id=%s, hash=%s",
            sealed.seal_id,
            sealed.content_hash[:16],
        )

        return SealResponse(
            seal_id=sealed.seal_id,
            signature=sealed.signature,
            algorithm_suite={
                "version": sealed.algorithm_suite.version,
                "hash_algorithm": sealed.algorithm_suite.hash_algorithm,
                "signature_algorithm": sealed.algorithm_suite.signature_algorithm,
                "key_size": sealed.algorithm_suite.key_size,
            },
            key_id=sealed.key_id,
            certificate_chain=sealed.certificate_chain,
            sealed_at=sealed.sealed_at.isoformat(),
            content_hash=sealed.content_hash,
            qualification_label=sealed.qualification_label.value,
            policy_snapshot_id=sealed.policy_snapshot_id,
        )

    except QualifiedModeNotImplementedError as e:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Qualified mode requires HSM integration (not yet implemented)",
        ) from e
    except TrustServiceError as e:
        logger.error("Seal operation failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        ) from e


@router.post(
    "/timestamp",
    response_model=TimestampResponse,
    summary="Get RFC 3161 timestamp token",
    responses={
        200: {"description": "Timestamp created successfully"},
        400: {"description": "Invalid input data"},
    },
)
async def create_timestamp(
    request: TimestampRequest,
    service: Annotated[TrustService, Depends(get_trust_service)],
) -> TimestampResponse:
    """Create an RFC 3161-style timestamp token.

    Per REQ-C03, provides time attestation over the provided data.
    In non-qualified mode, the timestamp is signed by the service's
    TSA key but clearly labeled as non-qualified.
    """
    try:
        # Decode base64 input
        try:
            data = base64.b64decode(request.data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 encoding in data field",
            ) from e

        # Create timestamp
        token = await service.timestamp(data, hash_algorithm=request.hash_algorithm)

        logger.info(
            "Created timestamp: token_id=%s, time=%s",
            token.token_id,
            token.timestamp.isoformat(),
        )

        return TimestampResponse(
            token_id=token.token_id,
            timestamp=token.timestamp.isoformat(),
            message_imprint=token.message_imprint,
            hash_algorithm=token.hash_algorithm,
            serial_number=token.serial_number,
            tsa_name=token.tsa_name,
            signature=token.signature,
            policy_oid=token.policy_oid,
            qualification_label=token.qualification_label.value,
            accuracy_seconds=token.accuracy_seconds,
        )

    except TrustServiceError as e:
        logger.error("Timestamp operation failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        ) from e


@router.post(
    "/checkpoint",
    response_model=CheckpointResponse,
    summary="Seal audit log checkpoint",
    responses={
        200: {"description": "Checkpoint created successfully"},
        400: {"description": "Invalid checkpoint data"},
    },
)
async def create_checkpoint(
    request: CheckpointRequest,
    service: Annotated[TrustService, Depends(get_trust_service)],
) -> CheckpointResponse:
    """Create a sealed and timestamped audit log checkpoint.

    Seals the current state of an audit log stream for tamper evidence.
    The checkpoint includes both a seal (signature) and timestamp.
    """
    try:
        checkpoint = await service.checkpoint(
            audit_log_hash=request.audit_log_hash,
            stream=request.stream,
            sequence_number=request.sequence_number,
        )

        logger.info(
            "Created checkpoint: id=%s, stream=%s, seq=%d",
            checkpoint.checkpoint_id,
            checkpoint.stream,
            checkpoint.sequence_number,
        )

        return CheckpointResponse(
            checkpoint_id=checkpoint.checkpoint_id,
            audit_log_hash=checkpoint.audit_log_hash,
            stream=checkpoint.stream,
            sequence_number=checkpoint.sequence_number,
            seal=SealResponse(
                seal_id=checkpoint.seal.seal_id,
                signature=checkpoint.seal.signature,
                algorithm_suite={
                    "version": checkpoint.seal.algorithm_suite.version,
                    "hash_algorithm": checkpoint.seal.algorithm_suite.hash_algorithm,
                    "signature_algorithm": checkpoint.seal.algorithm_suite.signature_algorithm,
                    "key_size": checkpoint.seal.algorithm_suite.key_size,
                },
                key_id=checkpoint.seal.key_id,
                certificate_chain=checkpoint.seal.certificate_chain,
                sealed_at=checkpoint.seal.sealed_at.isoformat(),
                content_hash=checkpoint.seal.content_hash,
                qualification_label=checkpoint.seal.qualification_label.value,
                policy_snapshot_id=checkpoint.seal.policy_snapshot_id,
            ),
            timestamp=TimestampResponse(
                token_id=checkpoint.timestamp.token_id,
                timestamp=checkpoint.timestamp.timestamp.isoformat(),
                message_imprint=checkpoint.timestamp.message_imprint,
                hash_algorithm=checkpoint.timestamp.hash_algorithm,
                serial_number=checkpoint.timestamp.serial_number,
                tsa_name=checkpoint.timestamp.tsa_name,
                signature=checkpoint.timestamp.signature,
                policy_oid=checkpoint.timestamp.policy_oid,
                qualification_label=checkpoint.timestamp.qualification_label.value,
                accuracy_seconds=checkpoint.timestamp.accuracy_seconds,
            ),
        )

    except TrustServiceError as e:
        logger.error("Checkpoint operation failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        ) from e


@router.get(
    "/keys",
    response_model=KeyInventoryResponse,
    summary="Get key inventory",
    responses={
        200: {"description": "Key inventory retrieved"},
    },
)
async def get_keys(
    service: Annotated[TrustService, Depends(get_trust_service)],
) -> KeyInventoryResponse:
    """Get metadata for all managed keys.

    Returns public key information only - no private material is exposed.
    Per REQ-H07, this supports key lifecycle ceremony evidence.
    """
    keys = await service.get_keys()

    return KeyInventoryResponse(
        keys=[
            KeyInfoResponse(
                key_id=k.key_id,
                purpose=k.purpose.value,
                algorithm={
                    "version": k.algorithm.version,
                    "hash_algorithm": k.algorithm.hash_algorithm,
                    "signature_algorithm": k.algorithm.signature_algorithm,
                    "key_size": k.algorithm.key_size,
                },
                status=k.status.value,
                created_at=k.created_at.isoformat(),
                expires_at=k.expires_at.isoformat() if k.expires_at else None,
                certificate_pem=k.certificate_pem,
                qualification_mode=k.qualification_mode.value,
            )
            for k in keys
        ],
        mode=service.mode.value,
    )


@router.get(
    "/keys/{key_id}",
    response_model=KeyInfoResponse,
    summary="Get specific key info",
    responses={
        200: {"description": "Key info retrieved"},
        404: {"description": "Key not found"},
    },
)
async def get_key(
    key_id: Annotated[str, Path(description="Key identifier")],
    service: Annotated[TrustService, Depends(get_trust_service)],
) -> KeyInfoResponse:
    """Get metadata for a specific key.

    Returns public key information only.
    """
    try:
        key = await service.get_key(key_id)
        return KeyInfoResponse(
            key_id=key.key_id,
            purpose=key.purpose.value,
            algorithm={
                "version": key.algorithm.version,
                "hash_algorithm": key.algorithm.hash_algorithm,
                "signature_algorithm": key.algorithm.signature_algorithm,
                "key_size": key.algorithm.key_size,
            },
            status=key.status.value,
            created_at=key.created_at.isoformat(),
            expires_at=key.expires_at.isoformat() if key.expires_at else None,
            certificate_pem=key.certificate_pem,
            qualification_mode=key.qualification_mode.value,
        )
    except KeyNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key not found: {key_id}",
        ) from e


@router.post(
    "/keys/{key_id}/rotate",
    response_model=KeyInfoResponse,
    summary="Rotate a key (dual-control required)",
    responses={
        200: {"description": "Key rotated successfully"},
        400: {"description": "Invalid rotation request"},
        404: {"description": "Key not found"},
        501: {"description": "Key rotation not yet implemented"},
    },
)
async def rotate_key(
    key_id: Annotated[str, Path(description="Key identifier to rotate")],
    request: RotationRequest,
    service: Annotated[TrustService, Depends(get_trust_service)],  # noqa: ARG001
) -> KeyInfoResponse:
    """Rotate a cryptographic key.

    Per REQ-H07, key rotation requires dual-control (second approver)
    and generates ceremony log evidence.

    NOTE: Key rotation is not yet implemented. This endpoint returns 501.
    """
    # Key rotation requires dual-control and ceremony logging
    # This is a placeholder for the full implementation
    logger.warning(
        "Key rotation requested for %s (not yet implemented): reason=%s",
        key_id,
        request.reason,
    )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Key rotation requires dual-control ceremony (not yet implemented)",
    )


# ---------------------------------------------------------------------------
# Service lifecycle management
# ---------------------------------------------------------------------------


async def initialize_trust_router(
    mode: QualificationMode = QualificationMode.NON_QUALIFIED,
    key_storage_path: str = "/keys",
    key_password: bytes | None = None,
    organization_name: str = "QERDS Development",
    country: str = "FR",
    policy_snapshot_id: str = "dev-policy-v1",
) -> None:
    """Initialize the trust service for the router.

    Should be called during application startup.

    Args:
        mode: Qualification mode.
        key_storage_path: Path for key storage.
        key_password: Password for key encryption.
        organization_name: Organization name for certificates.
        country: Country code for certificates.
        policy_snapshot_id: Policy snapshot identifier.
    """
    global _trust_service

    from pathlib import Path

    config = TrustServiceConfig(
        mode=mode,
        key_storage_path=Path(key_storage_path),
        key_password=key_password,
        organization_name=organization_name,
        country=country,
        policy_snapshot_id=policy_snapshot_id,
    )
    _trust_service = TrustService(config)
    await _trust_service.initialize()

    logger.info(
        "Trust router initialized: mode=%s, keys=%d",
        mode.value,
        len(await _trust_service.get_keys()),
    )


async def shutdown_trust_router() -> None:
    """Shutdown the trust service.

    Should be called during application shutdown.
    """
    global _trust_service
    _trust_service = None
    logger.info("Trust router shutdown")


def get_trust_service_for_testing(service: TrustService) -> None:
    """Inject a trust service instance for testing.

    Args:
        service: Configured TrustService instance.
    """
    global _trust_service
    _trust_service = service
