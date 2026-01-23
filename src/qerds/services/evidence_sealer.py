"""Evidence object sealing and timestamping service.

Covers: REQ-B02, REQ-C02, REQ-C03, REQ-G02

This module provides the evidence sealing logic that uses the TrustService
for cryptographic operations. It handles:

- Canonicalization of event data for deterministic signing
- Content binding via SHA-256 hashing
- Provider attestation via CMS seal
- Time attestation via RFC 3161 timestamp
- Verification bundle construction
- Storage of sealed evidence to object store

Per REQ-G02, all sealed evidence is labeled with its qualification status
(qualified/non_qualified) to prevent non-qualified outputs from being
misrepresented as compliant.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from qerds.services.storage import ObjectStoreClient
    from qerds.services.trust import SealedData, TimestampToken, TrustService

logger = logging.getLogger(__name__)


# Canonicalization version for tracking format changes over time
CANONICALIZATION_VERSION = "1.0"

# ETSI EN 319 522-4-1 format version identifier for forward compatibility
# Format: "ETSI-EN-319-522-4-1:<publication-date>"
ETSI_FORMAT_VERSION = "ETSI-EN-319-522-4-1:2024-01"


@dataclass(frozen=True, slots=True)
class VerificationBundle:
    """Verification material for independently verifying sealed evidence.

    Per REQ-H01, this bundle contains all material needed to verify
    the seal and timestamp without access to the original signing keys.

    Attributes:
        signing_cert_chain: PEM-encoded certificates for seal verification.
        tsa_cert_chain: PEM-encoded TSA certificates (if available).
        policy_oid: Timestamp policy OID used.
        hash_algorithm: Hash algorithm used for content binding.
        signature_algorithm: Signature algorithm used for sealing.
        algorithm_suite_version: Version of algorithm suite for crypto agility.
        created_at: When this bundle was created (ISO format).
    """

    signing_cert_chain: list[str]
    tsa_cert_chain: list[str]
    policy_oid: str
    hash_algorithm: str
    signature_algorithm: str
    algorithm_suite_version: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "signing_cert_chain": self.signing_cert_chain,
            "tsa_cert_chain": self.tsa_cert_chain,
            "policy_oid": self.policy_oid,
            "hash_algorithm": self.hash_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "algorithm_suite_version": self.algorithm_suite_version,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class SealedEvidence:
    """Complete sealed evidence object with all attestations.

    This dataclass represents a fully sealed evidence object containing:
    - The original payload (event data)
    - Content binding (cryptographic hash)
    - Provider attestation (CMS seal)
    - Time attestation (RFC 3161 timestamp)
    - Verification bundle (certs, policies, algorithms)
    - Qualification label (per REQ-G02)
    - ETSI format version (per EN 319 522-4-1)

    Attributes:
        evidence_id: Unique identifier for this sealed evidence.
        format_version: ETSI EN 319 522-4-1 format version for forward compatibility.
        payload: The original event data being sealed.
        canonical_bytes: Deterministic byte representation of payload.
        canonicalization_version: Version of canonicalization method used.
        content_hash: SHA-256 hash of canonical_bytes for content binding.
        provider_attestation: CMS seal from TrustService.
        time_attestation: RFC 3161 timestamp from TrustService.
        verification_bundle: Material needed for independent verification.
        qualification_label: 'qualified' or 'non_qualified' (REQ-G02).
        sealed_at: Timestamp when sealing was performed.
    """

    evidence_id: str
    format_version: str
    payload: dict[str, Any]
    canonical_bytes: bytes
    canonicalization_version: str
    content_hash: str
    provider_attestation: dict[str, Any]
    time_attestation: dict[str, Any]
    verification_bundle: VerificationBundle
    qualification_label: str
    sealed_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage and API responses.

        Returns the complete sealed evidence object in a serializable format.
        The canonical_bytes field is excluded as it can be recomputed from payload.
        """
        return {
            "evidence_id": self.evidence_id,
            "format_version": self.format_version,
            "payload": self.payload,
            "canonicalization_version": self.canonicalization_version,
            "content_hash": self.content_hash,
            "provider_attestation": self.provider_attestation,
            "time_attestation": self.time_attestation,
            "verification_bundle": self.verification_bundle.to_dict(),
            "qualification_label": self.qualification_label,
            "sealed_at": self.sealed_at.isoformat(),
        }

    def to_json(self) -> str:
        """Serialize to JSON string for storage.

        Uses canonical JSON formatting (sorted keys, minimal separators)
        for consistent storage format.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )


@dataclass(frozen=True, slots=True)
class StoredEvidenceResult:
    """Result of storing sealed evidence to object store.

    Attributes:
        evidence_id: ID of the sealed evidence.
        storage_key: Object key in the evidence bucket.
        bucket: Bucket name where evidence was stored.
        content_hash: SHA-256 hash of stored content.
        size_bytes: Size of stored evidence in bytes.
    """

    evidence_id: str
    storage_key: str
    bucket: str
    content_hash: str
    size_bytes: int


class EvidenceSealingError(Exception):
    """Base exception for evidence sealing operations."""

    pass


class CanonicalizationError(EvidenceSealingError):
    """Raised when canonicalization fails."""

    pass


class SealingError(EvidenceSealingError):
    """Raised when sealing operation fails."""

    pass


class StorageError(EvidenceSealingError):
    """Raised when evidence storage fails."""

    pass


@dataclass
class EvidenceSealerConfig:
    """Configuration for the evidence sealer.

    Attributes:
        evidence_bucket: Bucket name for storing sealed evidence.
        storage_prefix: Key prefix for evidence objects in bucket.
    """

    evidence_bucket: str = "qerds-evidence"
    storage_prefix: str = "sealed/"


class EvidenceSealer:
    """Service for sealing evidence objects with cryptographic attestations.

    This class orchestrates the evidence sealing workflow:
    1. Canonicalize event data to deterministic bytes
    2. Compute SHA-256 content binding hash
    3. Obtain provider attestation (CMS seal) via TrustService
    4. Obtain time attestation (RFC 3161 timestamp) via TrustService
    5. Build verification bundle with all required material
    6. Package into SealedEvidence object
    7. Optionally store to object storage

    Per REQ-G02, all outputs are labeled with qualification status.
    Non-qualified seals (dev mode) are clearly marked and must not be
    represented as compliant with qualified requirements.

    Example:
        trust_service = await create_trust_service(mode=QualificationMode.NON_QUALIFIED)
        sealer = EvidenceSealer(trust_service)

        event_data = {
            "event_id": "evt-123",
            "event_type": "EVT_DEPOSITED",
            "delivery_id": "del-456",
            ...
        }

        sealed = await sealer.seal_evidence(event_data)
        print(f"Sealed evidence: {sealed.evidence_id}")
        print(f"Qualification: {sealed.qualification_label}")

        # Store to S3
        result = await sealer.store_sealed_evidence(sealed, object_store_client)
    """

    def __init__(
        self,
        trust_service: TrustService,
        config: EvidenceSealerConfig | None = None,
    ) -> None:
        """Initialize the evidence sealer.

        Args:
            trust_service: Initialized TrustService for crypto operations.
            config: Optional configuration (uses defaults if not provided).
        """
        self._trust_service = trust_service
        self._config = config or EvidenceSealerConfig()

    @property
    def qualification_mode(self) -> str:
        """Get the current qualification mode from trust service."""
        return self._trust_service.mode.value

    def canonicalize(self, event_data: dict[str, Any]) -> bytes:
        """Create deterministic byte representation of event data.

        Per REQ-B02 and the spec, canonicalization must be:
        - Deterministic (same input always produces same output)
        - Versioned (changes to format are tracked)
        - Well-defined (unambiguous transformation)

        This implementation uses JSON with:
        - Sorted keys (alphabetical ordering)
        - Minimal separators (no whitespace)
        - UTF-8 encoding
        - Datetime objects converted to ISO format strings

        Args:
            event_data: Dictionary of event fields to canonicalize.

        Returns:
            Canonical UTF-8 encoded bytes.

        Raises:
            CanonicalizationError: If canonicalization fails.
        """
        try:
            # Build canonical JSON with sorted keys and compact separators
            canonical_json = json.dumps(
                event_data,
                sort_keys=True,
                separators=(",", ":"),
                default=self._json_serializer,
            )
            return canonical_json.encode("utf-8")
        except (TypeError, ValueError) as e:
            msg = f"Failed to canonicalize event data: {e}"
            raise CanonicalizationError(msg) from e

    def compute_content_hash(self, canonical_bytes: bytes) -> str:
        """Compute SHA-256 hash of canonical bytes for content binding.

        Per REQ-B02, the content hash cryptographically binds the
        evidence to its content, ensuring integrity can be verified.

        Args:
            canonical_bytes: Canonical byte representation of event data.

        Returns:
            Lowercase hex-encoded SHA-256 hash (64 characters).
        """
        return hashlib.sha256(canonical_bytes).hexdigest()

    async def seal_evidence(
        self,
        event_data: dict[str, Any],
        *,
        evidence_id: str | None = None,
    ) -> SealedEvidence:
        """Seal event data with provider and time attestations.

        This method orchestrates the complete sealing workflow:
        1. Canonicalize the event data
        2. Compute content binding hash
        3. Call TrustService.seal() for CMS signature
        4. Call TrustService.timestamp() for RFC 3161 timestamp
        5. Build verification bundle
        6. Return complete SealedEvidence object

        Args:
            event_data: Dictionary of event fields to seal.
            evidence_id: Optional custom evidence ID (generates UUID if not provided).

        Returns:
            SealedEvidence containing all attestations and verification material.

        Raises:
            CanonicalizationError: If canonicalization fails.
            SealingError: If seal or timestamp operations fail.
        """
        # Generate evidence ID if not provided
        if evidence_id is None:
            evidence_id = f"evd-{uuid.uuid4()}"

        sealed_at = datetime.now(UTC)

        # Step 1: Canonicalize event data
        canonical_bytes = self.canonicalize(event_data)

        # Step 2: Compute content binding hash
        content_hash = self.compute_content_hash(canonical_bytes)

        try:
            # Step 3: Get provider attestation (CMS seal)
            seal = await self._trust_service.seal(canonical_bytes)

            # Step 4: Get time attestation (RFC 3161 timestamp)
            # Timestamp the canonical bytes to bind time to content
            timestamp = await self._trust_service.timestamp(canonical_bytes)

        except Exception as e:
            msg = f"Trust service operation failed: {e}"
            raise SealingError(msg) from e

        # Step 5: Build verification bundle
        verification_bundle = self._build_verification_bundle(seal, timestamp)

        # Step 6: Create and return SealedEvidence
        logger.info(
            "Sealed evidence: evidence_id=%s, content_hash=%s, qualification=%s",
            evidence_id,
            content_hash[:16] + "...",
            self.qualification_mode,
        )

        return SealedEvidence(
            evidence_id=evidence_id,
            format_version=ETSI_FORMAT_VERSION,
            payload=event_data,
            canonical_bytes=canonical_bytes,
            canonicalization_version=CANONICALIZATION_VERSION,
            content_hash=content_hash,
            provider_attestation=seal.to_dict(),
            time_attestation=timestamp.to_dict(),
            verification_bundle=verification_bundle,
            qualification_label=self.qualification_mode,
            sealed_at=sealed_at,
        )

    async def store_sealed_evidence(
        self,
        sealed: SealedEvidence,
        object_store: ObjectStoreClient,
        *,
        key_prefix: str | None = None,
    ) -> StoredEvidenceResult:
        """Store sealed evidence to object storage.

        Stores the complete sealed evidence object as JSON in the
        configured evidence bucket. The storage key is derived from
        the evidence ID to enable retrieval.

        Args:
            sealed: The sealed evidence to store.
            object_store: ObjectStoreClient for S3 operations.
            key_prefix: Optional custom key prefix (uses config default if None).

        Returns:
            StoredEvidenceResult with storage location and metadata.

        Raises:
            StorageError: If storage operation fails.
        """
        prefix = key_prefix or self._config.storage_prefix
        storage_key = f"{prefix}{sealed.evidence_id}.json"

        # Serialize to JSON for storage
        evidence_json = sealed.to_json()
        evidence_bytes = evidence_json.encode("utf-8")

        try:
            # Ensure bucket exists before upload
            object_store.ensure_bucket(self._config.evidence_bucket)

            # Upload with metadata
            result = object_store.upload(
                bucket=self._config.evidence_bucket,
                key=storage_key,
                data=evidence_bytes,
                content_type="application/json",
                metadata={
                    "evidence-id": sealed.evidence_id,
                    "qualification-label": sealed.qualification_label,
                    "content-hash": sealed.content_hash,
                },
            )

            logger.info(
                "Stored sealed evidence: evidence_id=%s, key=%s, size=%d",
                sealed.evidence_id,
                storage_key,
                result.size_bytes,
            )

            return StoredEvidenceResult(
                evidence_id=sealed.evidence_id,
                storage_key=storage_key,
                bucket=self._config.evidence_bucket,
                content_hash=result.sha256_digest,
                size_bytes=result.size_bytes,
            )

        except Exception as e:
            msg = f"Failed to store sealed evidence {sealed.evidence_id}: {e}"
            raise StorageError(msg) from e

    def _build_verification_bundle(
        self,
        seal: SealedData,
        timestamp: TimestampToken,
    ) -> VerificationBundle:
        """Build verification bundle from seal and timestamp.

        The verification bundle contains all material needed to
        independently verify the sealed evidence without access
        to the original signing keys.

        Args:
            seal: Provider attestation from TrustService.
            timestamp: Time attestation from TrustService.

        Returns:
            VerificationBundle with certs, policies, and algorithms.
        """
        return VerificationBundle(
            signing_cert_chain=seal.certificate_chain,
            tsa_cert_chain=[],  # TSA certs would come from qualified TSA in production
            policy_oid=timestamp.policy_oid,
            hash_algorithm=seal.algorithm_suite.hash_algorithm,
            signature_algorithm=seal.algorithm_suite.signature_algorithm,
            algorithm_suite_version=seal.algorithm_suite.version,
            created_at=datetime.now(UTC).isoformat(),
        )

    @staticmethod
    def _json_serializer(obj: Any) -> str:
        """JSON serializer for objects not natively serializable.

        Handles datetime objects, UUIDs, and other common types
        for canonical JSON serialization.

        Args:
            obj: Object to serialize.

        Returns:
            String representation.

        Raises:
            TypeError: If object type is not supported.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__str__"):
            return str(obj)
        msg = f"Object of type {type(obj).__name__} is not JSON serializable"
        raise TypeError(msg)


async def create_evidence_sealer(
    trust_service: TrustService,
    *,
    evidence_bucket: str = "qerds-evidence",
    storage_prefix: str = "sealed/",
) -> EvidenceSealer:
    """Factory function to create an EvidenceSealer.

    Args:
        trust_service: Initialized TrustService instance.
        evidence_bucket: Bucket name for evidence storage.
        storage_prefix: Key prefix for evidence objects.

    Returns:
        Configured EvidenceSealer instance.
    """
    config = EvidenceSealerConfig(
        evidence_bucket=evidence_bucket,
        storage_prefix=storage_prefix,
    )
    return EvidenceSealer(trust_service, config)
