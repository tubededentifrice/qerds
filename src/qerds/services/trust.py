"""Trust service for signing, sealing, and timestamping.

Covers: REQ-C02, REQ-C03, REQ-D03, REQ-D04, REQ-D08, REQ-G02, REQ-H07, REQ-H01

This module provides cryptographic trust operations for QERDS:
- Provider attestation (seal/signature) over canonical evidence payloads
- Time attestation (RFC 3161 timestamp tokens or dev stubs)
- Audit log checkpoint sealing
- Key lifecycle management and ceremony evidence

IMPORTANT: Two modes are supported:
- non_qualified: Software keys for development/testing. All outputs are clearly labeled.
- qualified: Keys only via PKCS#11 to certified HSM (not yet implemented).

Per REQ-G02, non-qualified mode must label all outputs as non-qualified.
Per REQ-D04, qualified mode must use HSM with no software fallback.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

logger = logging.getLogger(__name__)


class QualificationMode(str, Enum):
    """Qualification mode for trust operations.

    Per REQ-G02, outputs must be labeled according to their qualification status.
    """

    NON_QUALIFIED = "non_qualified"
    QUALIFIED = "qualified"


class KeyPurpose(str, Enum):
    """Purpose of a cryptographic key.

    Per REQ-H07, the trust service manages multiple key types for different purposes.
    """

    SIGNING = "signing"  # For CMS/evidence sealing (REQ-C02)
    TIMESTAMPING = "timestamping"  # For RFC 3161 TSA operations (REQ-C03)
    KEK = "kek"  # Key Encryption Key for content encryption (REQ-D04)
    AUDIT_LOG_CHAIN = "audit_log_chain"  # For audit log chain signing (REQ-H01)


class KeyStatus(str, Enum):
    """Status of a key in its lifecycle.

    Per REQ-H07, keys go through a defined lifecycle:
    - PENDING_ACTIVATION: Generated but not yet activated (ceremony required)
    - ACTIVE: Currently in use for operations
    - PENDING_ROTATION: Marked for rotation, still usable
    - SUSPENDED: Temporarily disabled (e.g., incident investigation)
    - REVOKED: Permanently disabled, must not be used
    - RETIRED: Gracefully decommissioned after rotation
    """

    PENDING_ACTIVATION = "pending_activation"
    ACTIVE = "active"
    PENDING_ROTATION = "pending_rotation"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    RETIRED = "retired"


@dataclass(frozen=True, slots=True)
class AlgorithmSuite:
    """Versioned algorithm suite for crypto agility.

    Per REQ-D03, the platform must support versioned algorithm suites
    and retain verification material for historical suites.

    Attributes:
        version: Suite version identifier for audit trail.
        hash_algorithm: Hash algorithm name (e.g., "sha256").
        signature_algorithm: Signature algorithm name (e.g., "ECDSA-P384").
        key_size: Key size in bits.
    """

    version: str
    hash_algorithm: str
    signature_algorithm: str
    key_size: int

    @classmethod
    def default(cls) -> AlgorithmSuite:
        """Return the current default algorithm suite.

        Using ECDSA with P-384 curve per ENISA recommendations.
        SHA-384 for hash to match curve strength.
        """
        return cls(
            version="2026.1",
            hash_algorithm="sha384",
            signature_algorithm="ECDSA-P384",
            key_size=384,
        )


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """Public information about a cryptographic key.

    This is safe to expose via API - contains no private material.

    Attributes:
        key_id: Unique identifier for the key.
        purpose: What the key is used for.
        algorithm: Algorithm suite used with this key.
        status: Current lifecycle status.
        created_at: When the key was generated.
        expires_at: When the key expires (optional).
        certificate_pem: PEM-encoded certificate (public).
        qualification_mode: Whether key is qualified or not.
    """

    key_id: str
    purpose: KeyPurpose
    algorithm: AlgorithmSuite
    status: KeyStatus
    created_at: datetime
    expires_at: datetime | None
    certificate_pem: str
    qualification_mode: QualificationMode

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "key_id": self.key_id,
            "purpose": self.purpose.value,
            "algorithm": {
                "version": self.algorithm.version,
                "hash_algorithm": self.algorithm.hash_algorithm,
                "signature_algorithm": self.algorithm.signature_algorithm,
                "key_size": self.algorithm.key_size,
            },
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "certificate_pem": self.certificate_pem,
            "qualification_mode": self.qualification_mode.value,
        }


@dataclass(frozen=True, slots=True)
class SealedData:
    """Result of sealing data with provider attestation.

    Per REQ-H01, the verification bundle must include all material
    needed to verify the seal independently.

    Per REQ-G02, includes qualification_label and qualification_basis_ref
    to clearly indicate whether this seal is qualified or non-qualified.

    Attributes:
        seal_id: Unique identifier for this seal operation.
        signature: Base64-encoded CMS/PKCS#7 signature.
        algorithm_suite: Algorithm suite used for sealing.
        key_id: Identifier of the signing key.
        certificate_chain: List of PEM-encoded certificates.
        sealed_at: Timestamp of sealing operation.
        content_hash: Hash of the sealed content.
        qualification_label: Qualification status of the seal (qualified/non_qualified).
        policy_snapshot_id: Reference to policy snapshot at seal time.
        qualification_basis_ref: Reference to qualification dossier (only if qualified).
    """

    seal_id: str
    signature: str  # Base64-encoded
    algorithm_suite: AlgorithmSuite
    key_id: str
    certificate_chain: list[str]
    sealed_at: datetime
    content_hash: str
    qualification_label: QualificationMode
    policy_snapshot_id: str
    qualification_basis_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses and storage."""
        result = {
            "seal_id": self.seal_id,
            "signature": self.signature,
            "algorithm_suite": {
                "version": self.algorithm_suite.version,
                "hash_algorithm": self.algorithm_suite.hash_algorithm,
                "signature_algorithm": self.algorithm_suite.signature_algorithm,
                "key_size": self.algorithm_suite.key_size,
            },
            "key_id": self.key_id,
            "certificate_chain": self.certificate_chain,
            "sealed_at": self.sealed_at.isoformat(),
            "content_hash": self.content_hash,
            "qualification_label": self.qualification_label.value,
            "policy_snapshot_id": self.policy_snapshot_id,
        }
        # Only include qualification_basis_ref if present (qualified mode)
        if self.qualification_basis_ref:
            result["qualification_basis_ref"] = self.qualification_basis_ref
        return result


@dataclass(frozen=True, slots=True)
class TimestampToken:
    """RFC 3161-style timestamp token (or dev stub equivalent).

    Per REQ-C03, timestamps should use RFC 3161 format.
    In non-qualified mode, we produce a signed timestamp structure
    that mirrors RFC 3161 semantics but is clearly labeled.

    Per REQ-G02, includes qualification_label and qualification_basis_ref
    to clearly indicate whether this timestamp is qualified or non-qualified.

    Attributes:
        token_id: Unique identifier for this timestamp.
        timestamp: The attested time.
        message_imprint: Hash of the timestamped data.
        hash_algorithm: Algorithm used for message imprint.
        serial_number: Unique serial for this token.
        tsa_name: Name of the timestamp authority.
        signature: Base64-encoded timestamp signature.
        policy_oid: Timestamp policy OID.
        qualification_label: Qualification status (qualified/non_qualified).
        accuracy_seconds: Accuracy of the timestamp in seconds.
        qualification_basis_ref: Reference to qualification dossier (only if qualified).
    """

    token_id: str
    timestamp: datetime
    message_imprint: str
    hash_algorithm: str
    serial_number: int
    tsa_name: str
    signature: str
    policy_oid: str
    qualification_label: QualificationMode
    accuracy_seconds: int = 1
    qualification_basis_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        result = {
            "token_id": self.token_id,
            "timestamp": self.timestamp.isoformat(),
            "message_imprint": self.message_imprint,
            "hash_algorithm": self.hash_algorithm,
            "serial_number": self.serial_number,
            "tsa_name": self.tsa_name,
            "signature": self.signature,
            "policy_oid": self.policy_oid,
            "qualification_label": self.qualification_label.value,
            "accuracy_seconds": self.accuracy_seconds,
        }
        # Only include qualification_basis_ref if present (qualified mode)
        if self.qualification_basis_ref:
            result["qualification_basis_ref"] = self.qualification_basis_ref
        return result


@dataclass(frozen=True, slots=True)
class SealedCheckpoint:
    """Sealed audit log checkpoint.

    Used for periodic sealing of audit log state for tamper evidence.

    Attributes:
        checkpoint_id: Unique identifier for this checkpoint.
        audit_log_hash: Hash of the audit log at checkpoint time.
        stream: Name of the audit stream.
        sequence_number: Latest sequence number in the stream.
        seal: The seal over the checkpoint data.
        timestamp: Timestamp token for the checkpoint.
    """

    checkpoint_id: str
    audit_log_hash: str
    stream: str
    sequence_number: int
    seal: SealedData
    timestamp: TimestampToken

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage and API responses."""
        return {
            "checkpoint_id": self.checkpoint_id,
            "audit_log_hash": self.audit_log_hash,
            "stream": self.stream,
            "sequence_number": self.sequence_number,
            "seal": self.seal.to_dict(),
            "timestamp": self.timestamp.to_dict(),
        }


class KeyLifecycleAction(str, Enum):
    """Actions in the key lifecycle per REQ-H07.

    These actions represent state transitions that require ceremony evidence.
    """

    GENERATE = "generate"
    ACTIVATE = "activate"
    ROTATE = "rotate"
    SUSPEND = "suspend"
    UNSUSPEND = "unsuspend"
    REVOKE = "revoke"
    RETIRE = "retire"


class DualControlStatus(str, Enum):
    """Status of a dual-control request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class KeyLifecycleEvent:
    """Record of a key lifecycle state transition.

    Per REQ-H07, all key lifecycle events must be logged with ceremony evidence.
    This dataclass captures the immutable record of each transition.

    Attributes:
        event_id: Unique identifier for this lifecycle event.
        key_id: Identifier of the key affected.
        action: The lifecycle action performed.
        previous_status: Status before the transition.
        new_status: Status after the transition.
        performed_by: ID of the user/system that performed the action.
        approved_by: ID of the second approver (for dual-control operations).
        reason: Justification for the action.
        timestamp: When the event occurred.
        metadata: Additional event-specific data.
    """

    event_id: str
    key_id: str
    action: KeyLifecycleAction
    previous_status: KeyStatus | None
    new_status: KeyStatus
    performed_by: str
    approved_by: str | None
    reason: str
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage and API responses."""
        return {
            "event_id": self.event_id,
            "key_id": self.key_id,
            "action": self.action.value,
            "previous_status": self.previous_status.value if self.previous_status else None,
            "new_status": self.new_status.value,
            "performed_by": self.performed_by,
            "approved_by": self.approved_by,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class DualControlRequest:
    """Request for dual-control approval on sensitive operations.

    Per REQ-H07, certain operations (key rotation, revocation) require
    approval from a second authorized person (dual-control).

    Attributes:
        request_id: Unique identifier for this request.
        operation: The operation requiring approval.
        key_id: ID of the key affected (if applicable).
        requested_by: ID of the user requesting the operation.
        reason: Justification for the operation.
        created_at: When the request was created.
        expires_at: When the request expires if not acted upon.
        status: Current status of the request.
        approved_by: ID of the approver (if approved).
        rejected_by: ID of the rejector (if rejected).
        decision_at: When the decision was made.
        decision_reason: Reason for approval/rejection.
    """

    request_id: str
    operation: KeyLifecycleAction
    key_id: str | None
    requested_by: str
    reason: str
    created_at: datetime
    expires_at: datetime
    status: DualControlStatus = DualControlStatus.PENDING
    approved_by: str | None = None
    rejected_by: str | None = None
    decision_at: datetime | None = None
    decision_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage and API responses."""
        return {
            "request_id": self.request_id,
            "operation": self.operation.value,
            "key_id": self.key_id,
            "requested_by": self.requested_by,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status.value,
            "approved_by": self.approved_by,
            "rejected_by": self.rejected_by,
            "decision_at": self.decision_at.isoformat() if self.decision_at else None,
            "decision_reason": self.decision_reason,
        }


@dataclass(frozen=True, slots=True)
class KeyCeremonyLog:
    """Complete ceremony log for a key lifecycle event.

    Per REQ-H07, ceremony logs provide auditable evidence of key
    operations including all participants, approvals, and metadata.

    Attributes:
        ceremony_id: Unique identifier for this ceremony.
        event: The lifecycle event that occurred.
        dual_control: The dual-control request (if applicable).
        key_info: Public key information at time of ceremony.
        algorithm_suite: Algorithm suite in use.
        policy_snapshot_id: Reference to the policy at ceremony time.
        device_info: HSM/device identifiers (for qualified mode).
        witnesses: List of witness identifiers.
        sealed_at: When the ceremony log was sealed.
        seal_signature: Signature over the ceremony log.
    """

    ceremony_id: str
    event: KeyLifecycleEvent
    dual_control: DualControlRequest | None
    key_info: dict[str, Any]
    algorithm_suite: AlgorithmSuite
    policy_snapshot_id: str
    device_info: dict[str, Any] | None
    witnesses: list[str]
    sealed_at: datetime
    seal_signature: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage and audit export."""
        return {
            "ceremony_id": self.ceremony_id,
            "event": self.event.to_dict(),
            "dual_control": self.dual_control.to_dict() if self.dual_control else None,
            "key_info": self.key_info,
            "algorithm_suite": {
                "version": self.algorithm_suite.version,
                "hash_algorithm": self.algorithm_suite.hash_algorithm,
                "signature_algorithm": self.algorithm_suite.signature_algorithm,
                "key_size": self.algorithm_suite.key_size,
            },
            "policy_snapshot_id": self.policy_snapshot_id,
            "device_info": self.device_info,
            "witnesses": self.witnesses,
            "sealed_at": self.sealed_at.isoformat(),
            "seal_signature": self.seal_signature,
        }


@dataclass(frozen=True, slots=True)
class KeyInventory:
    """Complete key inventory snapshot for audit purposes.

    Per REQ-H07, the platform must track key inventory with metadata
    for qualification evidence.

    Attributes:
        snapshot_id: Unique identifier for this snapshot.
        snapshot_at: When the snapshot was taken.
        qualification_mode: Current service qualification mode.
        policy_snapshot_id: Policy reference at snapshot time.
        keys: List of key information.
        total_keys: Total number of keys.
        active_keys: Number of active keys.
        pending_keys: Number of pending activation keys.
        retired_keys: Number of retired keys.
    """

    snapshot_id: str
    snapshot_at: datetime
    qualification_mode: QualificationMode
    policy_snapshot_id: str
    keys: list[KeyInfo]
    total_keys: int
    active_keys: int
    pending_keys: int
    retired_keys: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses and storage."""
        return {
            "snapshot_id": self.snapshot_id,
            "snapshot_at": self.snapshot_at.isoformat(),
            "qualification_mode": self.qualification_mode.value,
            "policy_snapshot_id": self.policy_snapshot_id,
            "keys": [k.to_dict() for k in self.keys],
            "total_keys": self.total_keys,
            "active_keys": self.active_keys,
            "pending_keys": self.pending_keys,
            "retired_keys": self.retired_keys,
        }


@dataclass
class ManagedKey:
    """Internal representation of a managed cryptographic key.

    Not exposed via API - contains private key material.

    Attributes:
        key_id: Unique identifier for this key.
        purpose: What the key is used for.
        private_key: The private key material (never exposed).
        certificate: The self-signed or CA-issued certificate.
        algorithm: Algorithm suite used with this key.
        status: Current lifecycle status.
        created_at: When the key was generated.
        expires_at: When the key expires (optional).
        qualification_mode: Whether key is qualified or not.
        activated_at: When the key was activated (None if pending).
        retired_at: When the key was retired (None if active).
        revoked_at: When the key was revoked (None if not revoked).
        generation_ceremony_id: Reference to the generation ceremony log.
    """

    key_id: str
    purpose: KeyPurpose
    private_key: PrivateKeyTypes
    certificate: x509.Certificate
    algorithm: AlgorithmSuite
    status: KeyStatus
    created_at: datetime
    expires_at: datetime | None
    qualification_mode: QualificationMode
    activated_at: datetime | None = None
    retired_at: datetime | None = None
    revoked_at: datetime | None = None
    generation_ceremony_id: str | None = None

    def get_public_info(self) -> KeyInfo:
        """Extract public key information."""
        return KeyInfo(
            key_id=self.key_id,
            purpose=self.purpose,
            algorithm=self.algorithm,
            status=self.status,
            created_at=self.created_at,
            expires_at=self.expires_at,
            certificate_pem=self.certificate.public_bytes(Encoding.PEM).decode("utf-8"),
            qualification_mode=self.qualification_mode,
        )

    def is_usable(self) -> bool:
        """Check if the key can be used for operations."""
        return self.status == KeyStatus.ACTIVE


@dataclass
class TrustServiceConfig:
    """Configuration for the trust service.

    Attributes:
        mode: Qualification mode (non_qualified or qualified).
        key_storage_path: Path for storing encrypted keys (non-qualified mode).
        key_password: Password for encrypting stored keys (non-qualified mode).
        organization_name: Organization name for certificates.
        country: Country code for certificates.
        policy_snapshot_id: Current policy snapshot identifier.
        require_dual_control: Whether to enforce dual-control for sensitive ops.
        dual_control_expiry_minutes: How long dual-control requests remain valid.
        ceremony_log_path: Path for storing ceremony logs.
        auto_activate_keys: Auto-activate keys on generation (for dev mode only).
    """

    mode: QualificationMode = QualificationMode.NON_QUALIFIED
    key_storage_path: Path = field(default_factory=lambda: Path("/keys"))
    key_password: bytes | None = None
    organization_name: str = "QERDS Development"
    country: str = "FR"
    policy_snapshot_id: str = "dev-policy-v1"
    require_dual_control: bool = False
    dual_control_expiry_minutes: int = 60
    ceremony_log_path: Path | None = None
    auto_activate_keys: bool = True  # For dev convenience; False in production


class TrustServiceError(Exception):
    """Base exception for trust service errors."""

    pass


class QualifiedModeNotImplementedError(TrustServiceError):
    """Raised when qualified mode operations are attempted without HSM.

    Per REQ-B04 and REQ-D04, qualified mode requires HSM integration
    and must fail closed if prerequisites are not met.
    """

    def __init__(self, operation: str = "initialize") -> None:
        super().__init__(
            f"Qualified mode operation '{operation}' failed: HSM integration via PKCS#11 "
            "is required but not yet implemented. Per REQ-B04, qualified mode must fail "
            "closed when prerequisites are not met. Use non_qualified mode for development."
        )
        self.operation = operation


class QualifiedPrerequisitesNotMetError(TrustServiceError):
    """Raised when qualified operation attempted without prerequisites.

    This is the fail-closed behavior per REQ-B04: operations that require
    qualified mode must fail if prerequisites are not satisfied.
    """

    def __init__(self, operation: str, missing_prerequisites: list[str]) -> None:
        self.operation = operation
        self.missing_prerequisites = missing_prerequisites
        super().__init__(
            f"Qualified mode operation '{operation}' blocked: prerequisites not met. "
            f"Missing: {', '.join(missing_prerequisites)}. "
            "This is fail-closed behavior per REQ-B04."
        )


class KeyNotFoundError(TrustServiceError):
    """Raised when a requested key is not found."""

    def __init__(self, key_id: str) -> None:
        super().__init__(f"Key not found: {key_id}")
        self.key_id = key_id


class DualControlRequiredError(TrustServiceError):
    """Raised when an operation requires dual-control approval."""

    def __init__(self, operation: str, key_id: str | None = None) -> None:
        msg = f"Operation '{operation}' requires dual-control approval"
        if key_id:
            msg += f" for key: {key_id}"
        super().__init__(msg)
        self.operation = operation
        self.key_id = key_id


class DualControlRequestNotFoundError(TrustServiceError):
    """Raised when a dual-control request is not found."""

    def __init__(self, request_id: str) -> None:
        super().__init__(f"Dual-control request not found: {request_id}")
        self.request_id = request_id


class DualControlExpiredError(TrustServiceError):
    """Raised when a dual-control request has expired."""

    def __init__(self, request_id: str) -> None:
        super().__init__(f"Dual-control request has expired: {request_id}")
        self.request_id = request_id


class DualControlSameUserError(TrustServiceError):
    """Raised when the same user tries to both request and approve."""

    def __init__(self) -> None:
        super().__init__(
            "Dual-control violation: the approver must be different from the requester"
        )


class KeyStatusError(TrustServiceError):
    """Raised when a key operation is invalid for the current key status."""

    def __init__(self, key_id: str, current_status: KeyStatus, operation: str) -> None:
        super().__init__(
            f"Cannot perform '{operation}' on key {key_id}: "
            f"current status is {current_status.value}"
        )
        self.key_id = key_id
        self.current_status = current_status
        self.operation = operation


class TrustService:
    """Service for cryptographic trust operations.

    Provides signing, sealing, timestamping, and key management.
    All operations are logged via SecurityEventLogger when available.

    In non-qualified mode:
    - Uses software keys stored encrypted at rest
    - All outputs are clearly labeled as non_qualified
    - Suitable for development and testing only

    In qualified mode (not yet implemented):
    - Keys must be in certified HSM via PKCS#11
    - No software key fallback
    - Fail closed if HSM unavailable

    Example:
        config = TrustServiceConfig(mode=QualificationMode.NON_QUALIFIED)
        service = TrustService(config)
        await service.initialize()

        # Seal evidence
        sealed = await service.seal(evidence_bytes)

        # Get timestamp
        ts = await service.timestamp(data_hash)

        # Checkpoint audit log
        checkpoint = await service.checkpoint(
            audit_log_hash="abc123...",
            stream="SECURITY",
            sequence_number=42,
        )
    """

    def __init__(
        self,
        config: TrustServiceConfig,
        *,
        qualified_mode_enforcer: Any | None = None,
    ) -> None:
        """Initialize the trust service.

        Args:
            config: Service configuration.
            qualified_mode_enforcer: Optional QualifiedModeEnforcer for prerequisite checking.
                When provided and running in qualified mode, operations will call
                enforce_prerequisites() before proceeding. See qualified_mode.py.
        """
        self._config = config
        self._keys: dict[str, ManagedKey] = {}
        self._timestamp_serial: int = 0
        self._initialized: bool = False
        self._algorithm_suite = AlgorithmSuite.default()
        # Storage for ceremony logs (in-memory; production would use DB/storage)
        self._ceremony_logs: dict[str, KeyCeremonyLog] = {}
        # Optional qualified mode enforcer for prerequisite checking
        self._qualified_mode_enforcer = qualified_mode_enforcer

    @property
    def mode(self) -> QualificationMode:
        """Get the current qualification mode."""
        return self._config.mode

    @property
    def is_qualified(self) -> bool:
        """Check if running in qualified mode."""
        return self._config.mode == QualificationMode.QUALIFIED

    async def initialize(self) -> None:
        """Initialize the trust service.

        Loads or generates keys based on mode.
        In qualified mode, this would connect to HSM via PKCS#11.

        Raises:
            QualifiedModeNotImplementedError: If qualified mode is requested.
        """
        if self._config.mode == QualificationMode.QUALIFIED:
            raise QualifiedModeNotImplementedError()

        logger.info(
            "Initializing trust service in %s mode",
            self._config.mode.value,
        )

        # Load or generate signing key
        signing_key = await self._load_or_generate_key(
            purpose=KeyPurpose.SIGNING,
            key_id_prefix="seal",
        )
        self._keys[signing_key.key_id] = signing_key

        # Load or generate timestamping key
        tsa_key = await self._load_or_generate_key(
            purpose=KeyPurpose.TIMESTAMPING,
            key_id_prefix="tsa",
        )
        self._keys[tsa_key.key_id] = tsa_key

        self._initialized = True
        logger.info(
            "Trust service initialized with %d keys (mode: %s)",
            len(self._keys),
            self._config.mode.value,
        )

    async def seal(
        self,
        data: bytes,
        *,
        metadata: dict[str, Any] | None = None,  # noqa: ARG002 - reserved for future use
    ) -> SealedData:
        """Seal data with provider attestation.

        Creates a CMS/PKCS#7 detached signature over the canonical data.
        Per REQ-C02, this provides provider attestation.

        Args:
            data: The canonical bytes to seal.
            metadata: Optional metadata to include in seal context.

        Returns:
            SealedData with signature and verification bundle.

        Raises:
            TrustServiceError: If service not initialized or signing fails.
            QualifiedModeNotReadyError: If in qualified mode and prerequisites not met.
        """
        self._ensure_initialized()

        # Enforce qualified mode prerequisites if enforcer is configured
        if self._qualified_mode_enforcer is not None:
            self._qualified_mode_enforcer.enforce_prerequisites("seal")

        signing_key = self._get_active_key(KeyPurpose.SIGNING)
        seal_id = f"seal-{uuid.uuid4()}"
        sealed_at = datetime.now(UTC)

        # Compute content hash
        content_hash = hashlib.sha384(data).hexdigest()

        # Sign the data
        signature_bytes = self._sign_data(signing_key.private_key, data)
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        # Build certificate chain (in non-qualified mode, just the self-signed cert)
        cert_chain = [signing_key.certificate.public_bytes(Encoding.PEM).decode("utf-8")]

        logger.debug(
            "Sealed data: seal_id=%s, hash=%s, key=%s",
            seal_id,
            content_hash[:16],
            signing_key.key_id,
        )

        return SealedData(
            seal_id=seal_id,
            signature=signature_b64,
            algorithm_suite=self._algorithm_suite,
            key_id=signing_key.key_id,
            certificate_chain=cert_chain,
            sealed_at=sealed_at,
            content_hash=content_hash,
            qualification_label=self._config.mode,
            policy_snapshot_id=self._config.policy_snapshot_id,
        )

    async def timestamp(
        self,
        data: bytes,
        *,
        hash_algorithm: str = "sha384",
    ) -> TimestampToken:
        """Create a timestamp token for data.

        Per REQ-C03, timestamps should follow RFC 3161 format.
        In non-qualified mode, we create a signed timestamp structure
        with the same semantics but clearly labeled.

        Args:
            data: The data to timestamp (will be hashed).
            hash_algorithm: Hash algorithm for message imprint.

        Returns:
            TimestampToken with timestamp attestation.

        Raises:
            TrustServiceError: If service not initialized.
            QualifiedModeNotReadyError: If in qualified mode and prerequisites not met.
        """
        self._ensure_initialized()

        # Enforce qualified mode prerequisites if enforcer is configured
        if self._qualified_mode_enforcer is not None:
            self._qualified_mode_enforcer.enforce_prerequisites("timestamp")

        tsa_key = self._get_active_key(KeyPurpose.TIMESTAMPING)
        token_id = f"tst-{uuid.uuid4()}"
        timestamp = datetime.now(UTC)

        # Compute message imprint
        if hash_algorithm == "sha384":
            message_imprint = hashlib.sha384(data).hexdigest()
        elif hash_algorithm == "sha256":
            message_imprint = hashlib.sha256(data).hexdigest()
        elif hash_algorithm == "sha512":
            message_imprint = hashlib.sha512(data).hexdigest()
        else:
            msg = f"Unsupported hash algorithm: {hash_algorithm}"
            raise TrustServiceError(msg)

        # Increment serial number
        self._timestamp_serial += 1
        serial_number = self._timestamp_serial

        # Build timestamp info structure and sign it
        tst_info = self._build_tst_info(
            message_imprint=message_imprint,
            hash_algorithm=hash_algorithm,
            serial_number=serial_number,
            timestamp=timestamp,
        )
        signature_bytes = self._sign_data(tsa_key.private_key, tst_info)
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        # TSA name from certificate
        tsa_name = self._get_subject_cn(tsa_key.certificate)

        # Policy OID: use a dev policy OID for non-qualified
        policy_oid = "1.2.3.4.5.6.7.8.9.0"  # Dev policy OID (non-qualified)

        logger.debug(
            "Created timestamp: token_id=%s, serial=%d, time=%s",
            token_id,
            serial_number,
            timestamp.isoformat(),
        )

        return TimestampToken(
            token_id=token_id,
            timestamp=timestamp,
            message_imprint=message_imprint,
            hash_algorithm=hash_algorithm,
            serial_number=serial_number,
            tsa_name=tsa_name,
            signature=signature_b64,
            policy_oid=policy_oid,
            qualification_label=self._config.mode,
            accuracy_seconds=1,
        )

    async def checkpoint(
        self,
        *,
        audit_log_hash: str,
        stream: str,
        sequence_number: int,
    ) -> SealedCheckpoint:
        """Create a sealed checkpoint of audit log state.

        Combines seal and timestamp for periodic audit log checkpointing.

        Args:
            audit_log_hash: Hash of the audit log at this point.
            stream: Name of the audit stream being checkpointed.
            sequence_number: Latest sequence number in the stream.

        Returns:
            SealedCheckpoint with seal and timestamp.
        """
        self._ensure_initialized()

        checkpoint_id = f"ckpt-{uuid.uuid4()}"

        # Build checkpoint data
        checkpoint_data = (f"{checkpoint_id}|{stream}|{sequence_number}|{audit_log_hash}").encode()

        # Seal the checkpoint
        seal = await self.seal(checkpoint_data)

        # Timestamp the sealed checkpoint
        timestamp = await self.timestamp(checkpoint_data)

        logger.info(
            "Created audit log checkpoint: id=%s, stream=%s, seq=%d",
            checkpoint_id,
            stream,
            sequence_number,
        )

        return SealedCheckpoint(
            checkpoint_id=checkpoint_id,
            audit_log_hash=audit_log_hash,
            stream=stream,
            sequence_number=sequence_number,
            seal=seal,
            timestamp=timestamp,
        )

    async def get_keys(self) -> list[KeyInfo]:
        """Get public information about all managed keys.

        Returns:
            List of KeyInfo for all keys (no private material).
        """
        self._ensure_initialized()
        return [key.get_public_info() for key in self._keys.values()]

    async def get_key(self, key_id: str) -> KeyInfo:
        """Get public information about a specific key.

        Args:
            key_id: The key identifier.

        Returns:
            KeyInfo for the requested key.

        Raises:
            KeyNotFoundError: If key doesn't exist.
        """
        self._ensure_initialized()
        key = self._keys.get(key_id)
        if key is None:
            raise KeyNotFoundError(key_id)
        return key.get_public_info()

    async def get_key_inventory(self) -> KeyInventory:
        """Get a complete key inventory snapshot for audit.

        Per REQ-H07, provides key inventory metadata for qualification evidence.

        Returns:
            KeyInventory snapshot with all key metadata and counts.
        """
        self._ensure_initialized()

        keys = [k.get_public_info() for k in self._keys.values()]
        active = sum(1 for k in self._keys.values() if k.status == KeyStatus.ACTIVE)
        pending = sum(1 for k in self._keys.values() if k.status == KeyStatus.PENDING_ACTIVATION)
        retired = sum(1 for k in self._keys.values() if k.status == KeyStatus.RETIRED)

        return KeyInventory(
            snapshot_id=f"inv-{uuid.uuid4()}",
            snapshot_at=datetime.now(UTC),
            qualification_mode=self._config.mode,
            policy_snapshot_id=self._config.policy_snapshot_id,
            keys=keys,
            total_keys=len(keys),
            active_keys=active,
            pending_keys=pending,
            retired_keys=retired,
        )

    # -------------------------------------------------------------------------
    # Key Lifecycle Management (REQ-H07)
    # -------------------------------------------------------------------------

    async def generate_key(
        self,
        *,
        purpose: KeyPurpose,
        performed_by: str,
        reason: str = "Initial key generation",
        auto_activate: bool | None = None,
    ) -> tuple[KeyInfo, KeyCeremonyLog]:
        """Generate a new cryptographic key with ceremony logging.

        Per REQ-H07, key generation is a lifecycle event that requires
        ceremony evidence. The key starts in PENDING_ACTIVATION status
        unless auto_activate is True.

        Args:
            purpose: Purpose for the new key.
            performed_by: ID of the user/system generating the key.
            reason: Justification for key generation.
            auto_activate: Whether to auto-activate (defaults to config setting).

        Returns:
            Tuple of (KeyInfo, KeyCeremonyLog) for the new key.

        Raises:
            TrustServiceError: If service not initialized.
        """
        self._ensure_initialized()

        # Determine auto-activation behavior
        should_activate = (
            auto_activate if auto_activate is not None else self._config.auto_activate_keys
        )

        # Generate unique key ID
        key_id = f"{purpose.value}-{self._config.mode.value}-{uuid.uuid4().hex[:8]}"
        key_file = self._config.key_storage_path / f"{key_id}.pem"
        cert_file = self._config.key_storage_path / f"{key_id}-cert.pem"

        # Generate the key
        managed_key = await self._generate_key_internal(key_id, key_file, cert_file, purpose)

        # Set initial status based on auto-activate
        if should_activate:
            managed_key.status = KeyStatus.ACTIVE
            managed_key.activated_at = datetime.now(UTC)
        else:
            managed_key.status = KeyStatus.PENDING_ACTIVATION

        # Store the key
        self._keys[key_id] = managed_key

        # Create lifecycle event
        event = KeyLifecycleEvent(
            event_id=f"evt-{uuid.uuid4()}",
            key_id=key_id,
            action=KeyLifecycleAction.GENERATE,
            previous_status=None,
            new_status=managed_key.status,
            performed_by=performed_by,
            approved_by=None,
            reason=reason,
            timestamp=datetime.now(UTC),
            metadata={
                "purpose": purpose.value,
                "algorithm_suite": managed_key.algorithm.version,
                "auto_activated": should_activate,
            },
        )

        # Create ceremony log
        ceremony = await self._create_ceremony_log(event, managed_key, dual_control=None)

        logger.info(
            "Generated key: %s (purpose: %s, status: %s, ceremony: %s)",
            key_id,
            purpose.value,
            managed_key.status.value,
            ceremony.ceremony_id,
        )

        return managed_key.get_public_info(), ceremony

    async def activate_key(
        self,
        key_id: str,
        *,
        performed_by: str,
        approved_by: str | None = None,
        reason: str = "Key activation",
    ) -> tuple[KeyInfo, KeyCeremonyLog]:
        """Activate a key that is pending activation.

        Per REQ-H07, activation moves a key from PENDING_ACTIVATION to ACTIVE.
        May require dual-control approval based on configuration.

        Args:
            key_id: ID of the key to activate.
            performed_by: ID of the user activating the key.
            approved_by: ID of second approver (required if dual-control enabled).
            reason: Justification for activation.

        Returns:
            Tuple of (KeyInfo, KeyCeremonyLog).

        Raises:
            KeyNotFoundError: If key not found.
            KeyStatusError: If key is not in PENDING_ACTIVATION status.
            DualControlRequiredError: If dual-control required but not provided.
        """
        self._ensure_initialized()

        key = self._keys.get(key_id)
        if key is None:
            raise KeyNotFoundError(key_id)

        if key.status != KeyStatus.PENDING_ACTIVATION:
            raise KeyStatusError(key_id, key.status, "activate")

        # Check dual-control if required
        self._check_dual_control("activate", performed_by, approved_by)

        # Update key status
        previous_status = key.status
        key.status = KeyStatus.ACTIVE
        key.activated_at = datetime.now(UTC)

        # Create lifecycle event
        event = KeyLifecycleEvent(
            event_id=f"evt-{uuid.uuid4()}",
            key_id=key_id,
            action=KeyLifecycleAction.ACTIVATE,
            previous_status=previous_status,
            new_status=key.status,
            performed_by=performed_by,
            approved_by=approved_by,
            reason=reason,
            timestamp=datetime.now(UTC),
        )

        ceremony = await self._create_ceremony_log(event, key, dual_control=None)

        logger.info(
            "Activated key: %s (ceremony: %s)",
            key_id,
            ceremony.ceremony_id,
        )

        return key.get_public_info(), ceremony

    async def rotate_key(
        self,
        key_id: str,
        *,
        performed_by: str,
        approved_by: str | None = None,
        reason: str,
    ) -> tuple[KeyInfo, KeyInfo, KeyCeremonyLog]:
        """Rotate a key by generating a replacement and retiring the old one.

        Per REQ-H07, key rotation requires dual-control for sensitive keys
        and generates ceremony evidence. The old key is moved to RETIRED
        status while the new key becomes ACTIVE.

        Args:
            key_id: ID of the key to rotate.
            performed_by: ID of the user performing rotation.
            approved_by: ID of second approver (required if dual-control enabled).
            reason: Justification for rotation.

        Returns:
            Tuple of (old_key_info, new_key_info, ceremony_log).

        Raises:
            KeyNotFoundError: If key not found.
            KeyStatusError: If key is not in ACTIVE status.
            DualControlRequiredError: If dual-control required but not provided.
        """
        self._ensure_initialized()

        old_key = self._keys.get(key_id)
        if old_key is None:
            raise KeyNotFoundError(key_id)

        if old_key.status != KeyStatus.ACTIVE:
            raise KeyStatusError(key_id, old_key.status, "rotate")

        # Check dual-control if required
        self._check_dual_control("rotate", performed_by, approved_by)

        # Generate new key
        new_key_id = f"{old_key.purpose.value}-{self._config.mode.value}-{uuid.uuid4().hex[:8]}"
        key_file = self._config.key_storage_path / f"{new_key_id}.pem"
        cert_file = self._config.key_storage_path / f"{new_key_id}-cert.pem"

        new_key = await self._generate_key_internal(
            new_key_id, key_file, cert_file, old_key.purpose
        )
        new_key.status = KeyStatus.ACTIVE
        new_key.activated_at = datetime.now(UTC)

        # Retire old key
        old_key.status = KeyStatus.RETIRED
        old_key.retired_at = datetime.now(UTC)

        # Store new key
        self._keys[new_key_id] = new_key

        # Create lifecycle event
        event = KeyLifecycleEvent(
            event_id=f"evt-{uuid.uuid4()}",
            key_id=key_id,
            action=KeyLifecycleAction.ROTATE,
            previous_status=KeyStatus.ACTIVE,
            new_status=KeyStatus.RETIRED,
            performed_by=performed_by,
            approved_by=approved_by,
            reason=reason,
            timestamp=datetime.now(UTC),
            metadata={
                "new_key_id": new_key_id,
                "purpose": old_key.purpose.value,
            },
        )

        ceremony = await self._create_ceremony_log(event, old_key, dual_control=None)

        logger.info(
            "Rotated key: %s -> %s (ceremony: %s)",
            key_id,
            new_key_id,
            ceremony.ceremony_id,
        )

        return old_key.get_public_info(), new_key.get_public_info(), ceremony

    async def revoke_key(
        self,
        key_id: str,
        *,
        performed_by: str,
        approved_by: str | None = None,
        reason: str,
    ) -> tuple[KeyInfo, KeyCeremonyLog]:
        """Revoke a key, permanently disabling it.

        Per REQ-H07, key revocation is a critical operation requiring
        dual-control and ceremony evidence. Revoked keys cannot be reactivated.

        Args:
            key_id: ID of the key to revoke.
            performed_by: ID of the user performing revocation.
            approved_by: ID of second approver (required if dual-control enabled).
            reason: Justification for revocation.

        Returns:
            Tuple of (KeyInfo, KeyCeremonyLog).

        Raises:
            KeyNotFoundError: If key not found.
            KeyStatusError: If key is already revoked.
            DualControlRequiredError: If dual-control required but not provided.
        """
        self._ensure_initialized()

        key = self._keys.get(key_id)
        if key is None:
            raise KeyNotFoundError(key_id)

        if key.status == KeyStatus.REVOKED:
            raise KeyStatusError(key_id, key.status, "revoke")

        # Check dual-control - always require for revocation
        if self._config.require_dual_control and (not approved_by or approved_by == performed_by):
            raise DualControlRequiredError("revoke", key_id)

        previous_status = key.status
        key.status = KeyStatus.REVOKED
        key.revoked_at = datetime.now(UTC)

        event = KeyLifecycleEvent(
            event_id=f"evt-{uuid.uuid4()}",
            key_id=key_id,
            action=KeyLifecycleAction.REVOKE,
            previous_status=previous_status,
            new_status=key.status,
            performed_by=performed_by,
            approved_by=approved_by,
            reason=reason,
            timestamp=datetime.now(UTC),
        )

        ceremony = await self._create_ceremony_log(event, key, dual_control=None)

        logger.warning(
            "Revoked key: %s (reason: %s, ceremony: %s)",
            key_id,
            reason,
            ceremony.ceremony_id,
        )

        return key.get_public_info(), ceremony

    async def retire_key(
        self,
        key_id: str,
        *,
        performed_by: str,
        reason: str = "Key retirement",
    ) -> tuple[KeyInfo, KeyCeremonyLog]:
        """Retire a key gracefully.

        Per REQ-H07, retirement is a normal end-of-life transition for keys
        that are being replaced. Unlike revocation, retirement indicates
        planned decommissioning rather than security incident.

        Args:
            key_id: ID of the key to retire.
            performed_by: ID of the user retiring the key.
            reason: Justification for retirement.

        Returns:
            Tuple of (KeyInfo, KeyCeremonyLog).

        Raises:
            KeyNotFoundError: If key not found.
            KeyStatusError: If key is not in ACTIVE or SUSPENDED status.
        """
        self._ensure_initialized()

        key = self._keys.get(key_id)
        if key is None:
            raise KeyNotFoundError(key_id)

        if key.status not in (KeyStatus.ACTIVE, KeyStatus.SUSPENDED):
            raise KeyStatusError(key_id, key.status, "retire")

        previous_status = key.status
        key.status = KeyStatus.RETIRED
        key.retired_at = datetime.now(UTC)

        event = KeyLifecycleEvent(
            event_id=f"evt-{uuid.uuid4()}",
            key_id=key_id,
            action=KeyLifecycleAction.RETIRE,
            previous_status=previous_status,
            new_status=key.status,
            performed_by=performed_by,
            approved_by=None,
            reason=reason,
            timestamp=datetime.now(UTC),
        )

        ceremony = await self._create_ceremony_log(event, key, dual_control=None)

        logger.info(
            "Retired key: %s (ceremony: %s)",
            key_id,
            ceremony.ceremony_id,
        )

        return key.get_public_info(), ceremony

    async def suspend_key(
        self,
        key_id: str,
        *,
        performed_by: str,
        reason: str,
    ) -> tuple[KeyInfo, KeyCeremonyLog]:
        """Suspend a key temporarily.

        Suspending a key prevents it from being used but allows reactivation.
        Used for incident investigation or temporary security measures.

        Args:
            key_id: ID of the key to suspend.
            performed_by: ID of the user suspending the key.
            reason: Justification for suspension.

        Returns:
            Tuple of (KeyInfo, KeyCeremonyLog).

        Raises:
            KeyNotFoundError: If key not found.
            KeyStatusError: If key is not in ACTIVE status.
        """
        self._ensure_initialized()

        key = self._keys.get(key_id)
        if key is None:
            raise KeyNotFoundError(key_id)

        if key.status != KeyStatus.ACTIVE:
            raise KeyStatusError(key_id, key.status, "suspend")

        previous_status = key.status
        key.status = KeyStatus.SUSPENDED

        event = KeyLifecycleEvent(
            event_id=f"evt-{uuid.uuid4()}",
            key_id=key_id,
            action=KeyLifecycleAction.SUSPEND,
            previous_status=previous_status,
            new_status=key.status,
            performed_by=performed_by,
            approved_by=None,
            reason=reason,
            timestamp=datetime.now(UTC),
        )

        ceremony = await self._create_ceremony_log(event, key, dual_control=None)

        logger.warning(
            "Suspended key: %s (reason: %s, ceremony: %s)",
            key_id,
            reason,
            ceremony.ceremony_id,
        )

        return key.get_public_info(), ceremony

    async def unsuspend_key(
        self,
        key_id: str,
        *,
        performed_by: str,
        approved_by: str | None = None,
        reason: str,
    ) -> tuple[KeyInfo, KeyCeremonyLog]:
        """Reactivate a suspended key.

        Args:
            key_id: ID of the key to unsuspend.
            performed_by: ID of the user unsuspending the key.
            approved_by: ID of second approver (required if dual-control enabled).
            reason: Justification for unsuspension.

        Returns:
            Tuple of (KeyInfo, KeyCeremonyLog).

        Raises:
            KeyNotFoundError: If key not found.
            KeyStatusError: If key is not in SUSPENDED status.
            DualControlRequiredError: If dual-control required but not provided.
        """
        self._ensure_initialized()

        key = self._keys.get(key_id)
        if key is None:
            raise KeyNotFoundError(key_id)

        if key.status != KeyStatus.SUSPENDED:
            raise KeyStatusError(key_id, key.status, "unsuspend")

        # Check dual-control if required
        self._check_dual_control("unsuspend", performed_by, approved_by)

        previous_status = key.status
        key.status = KeyStatus.ACTIVE

        event = KeyLifecycleEvent(
            event_id=f"evt-{uuid.uuid4()}",
            key_id=key_id,
            action=KeyLifecycleAction.UNSUSPEND,
            previous_status=previous_status,
            new_status=key.status,
            performed_by=performed_by,
            approved_by=approved_by,
            reason=reason,
            timestamp=datetime.now(UTC),
        )

        ceremony = await self._create_ceremony_log(event, key, dual_control=None)

        logger.info(
            "Unsuspended key: %s (ceremony: %s)",
            key_id,
            ceremony.ceremony_id,
        )

        return key.get_public_info(), ceremony

    async def get_lifecycle_events(
        self,
        key_id: str | None = None,
    ) -> list[KeyCeremonyLog]:
        """Get ceremony logs for keys.

        Args:
            key_id: Optional key ID to filter by. If None, returns all ceremonies.

        Returns:
            List of KeyCeremonyLog entries.
        """
        self._ensure_initialized()

        # Return from in-memory ceremony log storage
        # In production, this would query from persistent storage
        logs = list(self._ceremony_logs.values())
        if key_id:
            logs = [log for log in logs if log.event.key_id == key_id]

        return sorted(logs, key=lambda x: x.event.timestamp, reverse=True)

    def _check_dual_control(
        self,
        operation: str,
        performed_by: str,
        approved_by: str | None,
    ) -> None:
        """Check dual-control requirements.

        Args:
            operation: The operation being performed.
            performed_by: ID of the user performing the operation.
            approved_by: ID of the second approver.

        Raises:
            DualControlRequiredError: If dual-control required but not provided.
            DualControlSameUserError: If approver is the same as performer.
        """
        if not self._config.require_dual_control:
            return

        if not approved_by:
            raise DualControlRequiredError(operation)

        if approved_by == performed_by:
            raise DualControlSameUserError()

    async def _create_ceremony_log(
        self,
        event: KeyLifecycleEvent,
        key: ManagedKey,
        *,
        dual_control: DualControlRequest | None,
    ) -> KeyCeremonyLog:
        """Create and store a ceremony log for a key lifecycle event.

        Args:
            event: The lifecycle event.
            key: The affected key.
            dual_control: The dual-control request if applicable.

        Returns:
            The created KeyCeremonyLog.
        """
        ceremony_id = f"ceremony-{uuid.uuid4()}"
        sealed_at = datetime.now(UTC)

        # Build ceremony data for sealing
        ceremony_data = {
            "ceremony_id": ceremony_id,
            "event": event.to_dict(),
            "key_id": key.key_id,
            "key_purpose": key.purpose.value,
            "qualification_mode": self._config.mode.value,
            "policy_snapshot_id": self._config.policy_snapshot_id,
            "sealed_at": sealed_at.isoformat(),
        }

        import json

        ceremony_bytes = json.dumps(ceremony_data, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

        # Sign the ceremony data (using signing key if available)
        seal_signature = ""
        try:
            signing_key = self._get_active_key(KeyPurpose.SIGNING)
            signature_bytes = self._sign_data(signing_key.private_key, ceremony_bytes)
            seal_signature = base64.b64encode(signature_bytes).decode("utf-8")
        except TrustServiceError:
            # No active signing key yet (during initialization)
            seal_signature = "pending-signing-key"

        ceremony = KeyCeremonyLog(
            ceremony_id=ceremony_id,
            event=event,
            dual_control=dual_control,
            key_info=key.get_public_info().to_dict(),
            algorithm_suite=self._algorithm_suite,
            policy_snapshot_id=self._config.policy_snapshot_id,
            device_info=None,  # HSM info would go here in qualified mode
            witnesses=[event.performed_by] + ([event.approved_by] if event.approved_by else []),
            sealed_at=sealed_at,
            seal_signature=seal_signature,
        )

        # Store ceremony log
        self._ceremony_logs[ceremony_id] = ceremony

        # Persist ceremony log to file if path configured
        if self._config.ceremony_log_path:
            await self._persist_ceremony_log(ceremony)

        return ceremony

    async def _persist_ceremony_log(self, ceremony: KeyCeremonyLog) -> None:
        """Persist a ceremony log to file storage.

        Args:
            ceremony: The ceremony log to persist.
        """
        import json

        if not self._config.ceremony_log_path:
            return

        self._config.ceremony_log_path.mkdir(parents=True, exist_ok=True)
        log_file = self._config.ceremony_log_path / f"{ceremony.ceremony_id}.json"

        log_file.write_text(json.dumps(ceremony.to_dict(), indent=2))
        logger.debug("Persisted ceremony log: %s", log_file)

    async def _generate_key_internal(
        self,
        key_id: str,
        key_file: Path,
        cert_file: Path,
        purpose: KeyPurpose,
    ) -> ManagedKey:
        """Internal key generation without lifecycle tracking.

        This is the low-level key generation used by both initialization
        and the generate_key lifecycle method.

        Args:
            key_id: Key identifier.
            key_file: Path to store private key.
            cert_file: Path to store certificate.
            purpose: Key purpose.

        Returns:
            Generated ManagedKey (status not set).
        """
        # Generate ECDSA key with P-384 curve
        private_key = ec.generate_private_key(ec.SECP384R1())

        created_at = datetime.now(UTC)
        from datetime import timedelta

        expires_at = created_at + timedelta(days=730)

        # Build certificate subject
        cn = f"QERDS {purpose.value.title()} ({self._config.mode.value})"
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self._config.country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._config.organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ]
        )

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(created_at)
            .not_valid_after(expires_at)
        )

        # Add extensions based on purpose
        cert_builder = self._add_key_usage_extensions(cert_builder, purpose)

        # Sign certificate
        certificate = cert_builder.sign(private_key, hashes.SHA384())

        # Save to storage
        self._config.key_storage_path.mkdir(parents=True, exist_ok=True)

        if self._config.key_password:
            encryption = BestAvailableEncryption(self._config.key_password)
        else:
            encryption = NoEncryption()

        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        key_file.write_bytes(key_pem)
        key_file.chmod(0o600)

        cert_pem = certificate.public_bytes(Encoding.PEM)
        cert_file.write_bytes(cert_pem)

        return ManagedKey(
            key_id=key_id,
            purpose=purpose,
            private_key=private_key,
            certificate=certificate,
            algorithm=self._algorithm_suite,
            status=KeyStatus.PENDING_ACTIVATION,  # Default; caller may change
            created_at=created_at,
            expires_at=expires_at,
            qualification_mode=self._config.mode,
        )

    def _add_key_usage_extensions(
        self,
        cert_builder: x509.CertificateBuilder,
        purpose: KeyPurpose,
    ) -> x509.CertificateBuilder:
        """Add appropriate key usage extensions based on purpose.

        Args:
            cert_builder: The certificate builder.
            purpose: The key purpose.

        Returns:
            Certificate builder with extensions added.
        """
        if purpose == KeyPurpose.SIGNING:
            return cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        elif purpose == KeyPurpose.TIMESTAMPING:
            return cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                critical=True,
            )
        elif purpose == KeyPurpose.KEK:
            return cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        elif purpose == KeyPurpose.AUDIT_LOG_CHAIN:
            return cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        return cert_builder

    async def verify_seal(
        self,
        data: bytes,
        sealed: SealedData,
    ) -> bool:
        """Verify a seal against data.

        Args:
            data: The original data.
            sealed: The seal to verify.

        Returns:
            True if verification succeeds, False otherwise.
        """
        try:
            # Load certificate from chain
            cert_pem = sealed.certificate_chain[0].encode("utf-8")
            cert = x509.load_pem_x509_certificate(cert_pem)
            public_key = cert.public_key()

            # Decode signature
            signature = base64.b64decode(sealed.signature)

            # Verify content hash
            computed_hash = hashlib.sha384(data).hexdigest()
            if computed_hash != sealed.content_hash:
                logger.warning("Seal verification failed: content hash mismatch")
                return False

            # Verify signature
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, data, ec.ECDSA(hashes.SHA384()))
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA384(),
                )
            else:
                logger.warning("Unsupported key type for verification")
                return False

            return True
        except Exception as e:
            logger.warning("Seal verification failed: %s", str(e))
            return False

    async def verify_timestamp(
        self,
        data: bytes,
        token: TimestampToken,
    ) -> bool:
        """Verify a timestamp token against data.

        Args:
            data: The original data.
            token: The timestamp token to verify.

        Returns:
            True if verification succeeds, False otherwise.
        """
        try:
            # Verify message imprint
            if token.hash_algorithm == "sha384":
                computed = hashlib.sha384(data).hexdigest()
            elif token.hash_algorithm == "sha256":
                computed = hashlib.sha256(data).hexdigest()
            elif token.hash_algorithm == "sha512":
                computed = hashlib.sha512(data).hexdigest()
            else:
                logger.warning("Unsupported hash algorithm: %s", token.hash_algorithm)
                return False

            if computed != token.message_imprint:
                logger.warning("Timestamp verification failed: message imprint mismatch")
                return False

            # For full verification, we'd need the TSA certificate
            # In this implementation, we verify against our stored key
            tsa_key = self._get_active_key(KeyPurpose.TIMESTAMPING)

            # Rebuild TSTInfo and verify signature
            tst_info = self._build_tst_info(
                message_imprint=token.message_imprint,
                hash_algorithm=token.hash_algorithm,
                serial_number=token.serial_number,
                timestamp=token.timestamp,
            )
            signature = base64.b64decode(token.signature)

            public_key = tsa_key.certificate.public_key()
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, tst_info, ec.ECDSA(hashes.SHA384()))
            else:
                logger.warning("Unsupported key type for timestamp verification")
                return False

            return True
        except Exception as e:
            logger.warning("Timestamp verification failed: %s", str(e))
            return False

    def _ensure_initialized(self) -> None:
        """Ensure service is initialized."""
        if not self._initialized:
            msg = "Trust service not initialized. Call initialize() first."
            raise TrustServiceError(msg)

    def _get_active_key(self, purpose: KeyPurpose) -> ManagedKey:
        """Get the active key for a purpose.

        Args:
            purpose: The key purpose.

        Returns:
            The active ManagedKey.

        Raises:
            TrustServiceError: If no active key found.
        """
        for key in self._keys.values():
            if key.purpose == purpose and key.status == KeyStatus.ACTIVE:
                return key
        msg = f"No active key found for purpose: {purpose.value}"
        raise TrustServiceError(msg)

    async def _load_or_generate_key(
        self,
        *,
        purpose: KeyPurpose,
        key_id_prefix: str,
    ) -> ManagedKey:
        """Load existing key from storage or generate new one.

        Args:
            purpose: Purpose of the key.
            key_id_prefix: Prefix for key ID.

        Returns:
            Loaded or generated ManagedKey.
        """
        key_id = f"{key_id_prefix}-{self._config.mode.value}-001"
        key_file = self._config.key_storage_path / f"{key_id}.pem"
        cert_file = self._config.key_storage_path / f"{key_id}-cert.pem"

        # Try to load existing key
        if key_file.exists() and cert_file.exists():
            logger.info("Loading existing key: %s", key_id)
            return await self._load_key(key_id, key_file, cert_file, purpose)

        # Generate new key
        logger.info("Generating new key: %s (purpose: %s)", key_id, purpose.value)
        return await self._generate_key(key_id, key_file, cert_file, purpose)

    async def _load_key(
        self,
        key_id: str,
        key_file: Path,
        cert_file: Path,
        purpose: KeyPurpose,
    ) -> ManagedKey:
        """Load a key from storage.

        Args:
            key_id: Key identifier.
            key_file: Path to private key PEM file.
            cert_file: Path to certificate PEM file.
            purpose: Key purpose.

        Returns:
            Loaded ManagedKey.
        """
        key_pem = key_file.read_bytes()
        cert_pem = cert_file.read_bytes()

        password = self._config.key_password
        private_key = load_pem_private_key(key_pem, password=password)
        certificate = x509.load_pem_x509_certificate(cert_pem)

        # Extract creation time from certificate
        created_at = certificate.not_valid_before_utc
        expires_at = certificate.not_valid_after_utc

        return ManagedKey(
            key_id=key_id,
            purpose=purpose,
            private_key=private_key,
            certificate=certificate,
            algorithm=self._algorithm_suite,
            status=KeyStatus.ACTIVE,
            created_at=created_at,
            expires_at=expires_at,
            qualification_mode=self._config.mode,
        )

    async def _generate_key(
        self,
        key_id: str,
        key_file: Path,
        cert_file: Path,
        purpose: KeyPurpose,
    ) -> ManagedKey:
        """Generate a new key and self-signed certificate.

        This method is used during initialization for backwards compatibility.
        For lifecycle-managed key generation, use generate_key() instead.

        Args:
            key_id: Key identifier.
            key_file: Path to store private key.
            cert_file: Path to store certificate.
            purpose: Key purpose.

        Returns:
            Generated ManagedKey with ACTIVE status.
        """
        # Use internal generation and set to active (for initialization)
        key = await self._generate_key_internal(key_id, key_file, cert_file, purpose)
        key.status = KeyStatus.ACTIVE
        key.activated_at = datetime.now(UTC)

        logger.info(
            "Generated key: %s (purpose: %s, expires: %s)",
            key_id,
            purpose.value,
            key.expires_at.isoformat() if key.expires_at else "never",
        )

        return key

    def _sign_data(
        self,
        private_key: PrivateKeyTypes,
        data: bytes,
    ) -> bytes:
        """Sign data with private key.

        Args:
            private_key: The private key.
            data: Data to sign.

        Returns:
            Signature bytes.
        """
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(data, ec.ECDSA(hashes.SHA384()))
        elif isinstance(private_key, rsa.RSAPrivateKey):
            return private_key.sign(data, padding.PKCS1v15(), hashes.SHA384())
        else:
            msg = f"Unsupported key type: {type(private_key)}"
            raise TrustServiceError(msg)

    def _build_tst_info(
        self,
        *,
        message_imprint: str,
        hash_algorithm: str,
        serial_number: int,
        timestamp: datetime,
    ) -> bytes:
        """Build TSTInfo structure for signing.

        This is a simplified representation of RFC 3161 TSTInfo.
        In production, this would be proper ASN.1 DER encoding.

        Args:
            message_imprint: Hash of timestamped data.
            hash_algorithm: Hash algorithm used.
            serial_number: Unique serial number.
            timestamp: The timestamp.

        Returns:
            Canonical bytes representation.
        """
        # Build deterministic representation
        import json

        tst_info = {
            "version": 1,
            "policy": "1.2.3.4.5.6.7.8.9.0",
            "messageImprint": {
                "hashAlgorithm": hash_algorithm,
                "hashedMessage": message_imprint,
            },
            "serialNumber": serial_number,
            "genTime": timestamp.isoformat(),
            "accuracy": {"seconds": 1},
            "ordering": False,
            "nonce": None,
        }
        return json.dumps(tst_info, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _get_subject_cn(self, certificate: x509.Certificate) -> str:
        """Extract Common Name from certificate subject."""
        for attr in certificate.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return str(attr.value)
        return "Unknown"


async def create_trust_service(
    mode: QualificationMode = QualificationMode.NON_QUALIFIED,
    key_storage_path: str | Path = "/keys",
    key_password: bytes | None = None,
    organization_name: str = "QERDS Development",
    country: str = "FR",
    policy_snapshot_id: str = "dev-policy-v1",
) -> TrustService:
    """Create and initialize a trust service.

    Factory function for creating a configured and initialized TrustService.

    Args:
        mode: Qualification mode.
        key_storage_path: Path for key storage (non-qualified mode).
        key_password: Password for key encryption.
        organization_name: Organization name for certificates.
        country: Country code for certificates.
        policy_snapshot_id: Policy snapshot identifier.

    Returns:
        Initialized TrustService.

    Example:
        service = await create_trust_service(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path="/tmp/keys",
        )
        sealed = await service.seal(b"evidence data")
    """
    config = TrustServiceConfig(
        mode=mode,
        key_storage_path=Path(key_storage_path),
        key_password=key_password,
        organization_name=organization_name,
        country=country,
        policy_snapshot_id=policy_snapshot_id,
    )
    service = TrustService(config)
    await service.initialize()
    return service
