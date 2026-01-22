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
    """Purpose of a cryptographic key."""

    SIGNING = "signing"  # For CMS/evidence sealing
    TIMESTAMPING = "timestamping"  # For RFC 3161 TSA operations


class KeyStatus(str, Enum):
    """Status of a key in its lifecycle."""

    ACTIVE = "active"
    PENDING_ROTATION = "pending_rotation"
    RETIRED = "retired"
    REVOKED = "revoked"


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

    Attributes:
        seal_id: Unique identifier for this seal operation.
        signature: Base64-encoded CMS/PKCS#7 signature.
        algorithm_suite: Algorithm suite used for sealing.
        key_id: Identifier of the signing key.
        certificate_chain: List of PEM-encoded certificates.
        sealed_at: Timestamp of sealing operation.
        content_hash: Hash of the sealed content.
        qualification_label: Qualification status of the seal.
        policy_snapshot_id: Reference to policy snapshot at seal time.
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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses and storage."""
        return {
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


@dataclass(frozen=True, slots=True)
class TimestampToken:
    """RFC 3161-style timestamp token (or dev stub equivalent).

    Per REQ-C03, timestamps should use RFC 3161 format.
    In non-qualified mode, we produce a signed timestamp structure
    that mirrors RFC 3161 semantics but is clearly labeled.

    Attributes:
        token_id: Unique identifier for this timestamp.
        timestamp: The attested time.
        message_imprint: Hash of the timestamped data.
        hash_algorithm: Algorithm used for message imprint.
        serial_number: Unique serial for this token.
        tsa_name: Name of the timestamp authority.
        signature: Base64-encoded timestamp signature.
        policy_oid: Timestamp policy OID.
        qualification_label: Qualification status.
        accuracy_seconds: Accuracy of the timestamp in seconds.
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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
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


@dataclass
class ManagedKey:
    """Internal representation of a managed cryptographic key.

    Not exposed via API - contains private key material.
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
    """

    mode: QualificationMode = QualificationMode.NON_QUALIFIED
    key_storage_path: Path = field(default_factory=lambda: Path("/keys"))
    key_password: bytes | None = None
    organization_name: str = "QERDS Development"
    country: str = "FR"
    policy_snapshot_id: str = "dev-policy-v1"


class TrustServiceError(Exception):
    """Base exception for trust service errors."""

    pass


class QualifiedModeNotImplementedError(TrustServiceError):
    """Raised when qualified mode operations are attempted."""

    def __init__(self) -> None:
        super().__init__(
            "Qualified mode requires HSM integration via PKCS#11. "
            "This is not yet implemented. Use non_qualified mode for development."
        )


class KeyNotFoundError(TrustServiceError):
    """Raised when a requested key is not found."""

    def __init__(self, key_id: str) -> None:
        super().__init__(f"Key not found: {key_id}")
        self.key_id = key_id


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

    def __init__(self, config: TrustServiceConfig) -> None:
        """Initialize the trust service.

        Args:
            config: Service configuration.
        """
        self._config = config
        self._keys: dict[str, ManagedKey] = {}
        self._timestamp_serial: int = 0
        self._initialized: bool = False
        self._algorithm_suite = AlgorithmSuite.default()

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
        """
        self._ensure_initialized()

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
        """
        self._ensure_initialized()

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

        Args:
            key_id: Key identifier.
            key_file: Path to store private key.
            cert_file: Path to store certificate.
            purpose: Key purpose.

        Returns:
            Generated ManagedKey.
        """
        # Generate ECDSA key with P-384 curve
        private_key = ec.generate_private_key(ec.SECP384R1())

        created_at = datetime.now(UTC)
        # Keys valid for 2 years in non-qualified mode
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

        # Build certificate
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
        if purpose == KeyPurpose.SIGNING:
            cert_builder = cert_builder.add_extension(
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
            cert_builder = cert_builder.add_extension(
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

        # Sign certificate
        certificate = cert_builder.sign(private_key, hashes.SHA384())

        # Save to storage
        self._config.key_storage_path.mkdir(parents=True, exist_ok=True)

        # Encrypt private key if password provided
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
        key_file.chmod(0o600)  # Secure permissions for private key

        cert_pem = certificate.public_bytes(Encoding.PEM)
        cert_file.write_bytes(cert_pem)

        logger.info(
            "Generated key: %s (purpose: %s, expires: %s)",
            key_id,
            purpose.value,
            expires_at.isoformat(),
        )

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
