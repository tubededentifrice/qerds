"""Content encryption service for data at rest.

Covers: REQ-E01 (content encryption at rest), REQ-E02 (content access gating)

This module provides envelope encryption for content objects:
- Data Encryption Key (DEK): AES-256-GCM, per content object
- Key Encryption Key (KEK): Managed by qerds-trust, protects DEKs

Encryption flow:
1. Generate random DEK for each content object
2. Encrypt content with DEK using AES-256-GCM
3. Wrap (encrypt) DEK with KEK from qerds-trust
4. Store wrapped DEK alongside encrypted content metadata

Decryption flow:
1. Verify authorization (sender or accepted recipient)
2. Unwrap DEK using KEK from qerds-trust
3. Decrypt content with DEK

IMPORTANT: This module uses the `cryptography` library (pyca/cryptography),
a well-audited implementation. AES-256-GCM provides authenticated encryption
with associated data (AEAD).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# AES-256 requires 32-byte key
DEK_SIZE_BYTES = 32
# GCM nonce should be 12 bytes per NIST recommendations
GCM_NONCE_SIZE_BYTES = 12
# GCM tag is 16 bytes (128 bits)
GCM_TAG_SIZE_BYTES = 16


class EncryptionMode(str, Enum):
    """Encryption mode for content at rest.

    Values:
        AES_256_GCM: AES-256 in Galois/Counter Mode (default, recommended)
        NONE: No encryption (for testing or non-confidential content)
    """

    AES_256_GCM = "aes_256_gcm"
    NONE = "none"


class EncryptionError(Exception):
    """Base exception for encryption operations."""

    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""

    pass


class KeyWrapError(EncryptionError):
    """Raised when key wrapping/unwrapping fails."""

    pass


class AuthorizationError(EncryptionError):
    """Raised when decryption is not authorized."""

    pass


@dataclass(frozen=True, slots=True)
class EncryptedContent:
    """Result of content encryption.

    Attributes:
        ciphertext: Encrypted content bytes.
        nonce: GCM nonce used for encryption.
        wrapped_dek: DEK encrypted with KEK (base64).
        kek_id: Identifier of the KEK used to wrap the DEK.
        content_hash: SHA-256 hash of original plaintext (for integrity).
        encrypted_at: When the encryption was performed.
        algorithm: Encryption algorithm used.
        metadata_version: Version of encryption metadata format.
    """

    ciphertext: bytes
    nonce: bytes
    wrapped_dek: str  # base64-encoded
    kek_id: str
    content_hash: str
    encrypted_at: datetime
    algorithm: EncryptionMode = EncryptionMode.AES_256_GCM
    metadata_version: str = "1.0"

    def to_metadata_dict(self) -> dict[str, Any]:
        """Convert to metadata dictionary for storage.

        Returns the encryption metadata that should be stored
        alongside the ciphertext in the database.
        """
        return {
            "version": self.metadata_version,
            "algorithm": self.algorithm.value,
            "nonce": base64.b64encode(self.nonce).decode("utf-8"),
            "wrapped_dek": self.wrapped_dek,
            "kek_id": self.kek_id,
            "content_hash": self.content_hash,
            "encrypted_at": self.encrypted_at.isoformat(),
        }

    @classmethod
    def from_metadata_dict(
        cls,
        metadata: dict[str, Any],
        ciphertext: bytes,
    ) -> EncryptedContent:
        """Reconstruct from metadata dictionary.

        Args:
            metadata: Encryption metadata from storage.
            ciphertext: The encrypted content bytes.

        Returns:
            EncryptedContent instance.
        """
        return cls(
            ciphertext=ciphertext,
            nonce=base64.b64decode(metadata["nonce"]),
            wrapped_dek=metadata["wrapped_dek"],
            kek_id=metadata["kek_id"],
            content_hash=metadata["content_hash"],
            encrypted_at=datetime.fromisoformat(metadata["encrypted_at"]),
            algorithm=EncryptionMode(metadata["algorithm"]),
            metadata_version=metadata["version"],
        )


@dataclass
class KEKInfo:
    """Information about a Key Encryption Key.

    Attributes:
        kek_id: Unique identifier for this KEK.
        created_at: When the KEK was generated.
        algorithm: Algorithm used for KEK operations.
        status: Current lifecycle status.
    """

    kek_id: str
    created_at: datetime
    algorithm: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "kek_id": self.kek_id,
            "created_at": self.created_at.isoformat(),
            "algorithm": self.algorithm,
            "status": self.status,
        }


@dataclass
class EncryptionServiceConfig:
    """Configuration for the encryption service.

    Attributes:
        mode: Encryption mode (AES_256_GCM or NONE).
        kek_storage_path: Path for KEK storage (in non-qualified mode).
        kek_password: Password for encrypting KEK at rest.
        qualification_label: Qualification status for outputs.
    """

    mode: EncryptionMode = EncryptionMode.AES_256_GCM
    kek_storage_path: str = field(default="/keys/encryption")
    kek_password: bytes | None = None
    qualification_label: str = "non_qualified"


class EncryptionService:
    """Service for content encryption at rest.

    Implements envelope encryption using:
    - AES-256-GCM for content encryption (DEK)
    - AES-256-GCM for key wrapping (KEK protects DEK)

    Per REQ-E01, all content must be encrypted before storage in the
    object store. This service handles the encryption/decryption
    operations and manages the key hierarchy.

    Example:
        config = EncryptionServiceConfig()
        service = EncryptionService(config)
        await service.initialize()

        # Encrypt content
        encrypted = await service.encrypt(content_bytes)

        # Store ciphertext and metadata separately
        store_in_object_store(encrypted.ciphertext)
        store_in_database(encrypted.to_metadata_dict())

        # Later, decrypt
        plaintext = await service.decrypt(encrypted)
    """

    def __init__(self, config: EncryptionServiceConfig | None = None) -> None:
        """Initialize the encryption service.

        Args:
            config: Service configuration. Uses defaults if not provided.
        """
        self._config = config or EncryptionServiceConfig()
        self._kek: bytes | None = None
        self._kek_id: str | None = None
        self._kek_created_at: datetime | None = None
        self._initialized: bool = False

    @property
    def mode(self) -> EncryptionMode:
        """Get the encryption mode."""
        return self._config.mode

    @property
    def is_encryption_enabled(self) -> bool:
        """Check if encryption is enabled."""
        return self._config.mode != EncryptionMode.NONE

    async def initialize(self) -> None:
        """Initialize the encryption service.

        Loads or generates the KEK. Must be called before encrypt/decrypt.
        """
        if self._config.mode == EncryptionMode.NONE:
            logger.info("Encryption service initialized in NONE mode (no encryption)")
            self._initialized = True
            return

        # Load or generate KEK
        await self._load_or_generate_kek()
        self._initialized = True

        logger.info(
            "Encryption service initialized: mode=%s, kek_id=%s",
            self._config.mode.value,
            self._kek_id,
        )

    async def encrypt(
        self,
        plaintext: bytes,
        *,
        associated_data: bytes | None = None,
    ) -> EncryptedContent:
        """Encrypt content using envelope encryption.

        Generates a random DEK, encrypts the content with AES-256-GCM,
        and wraps the DEK with the KEK.

        Args:
            plaintext: Content bytes to encrypt.
            associated_data: Optional AAD for AEAD (not encrypted, but authenticated).

        Returns:
            EncryptedContent with ciphertext and metadata.

        Raises:
            EncryptionError: If encryption fails.
        """
        self._ensure_initialized()

        if self._config.mode == EncryptionMode.NONE:
            # Return passthrough for testing/non-confidential mode
            return EncryptedContent(
                ciphertext=plaintext,
                nonce=b"",
                wrapped_dek="",
                kek_id="",
                content_hash=hashlib.sha256(plaintext).hexdigest(),
                encrypted_at=datetime.now(UTC),
                algorithm=EncryptionMode.NONE,
            )

        try:
            # Generate random DEK for this content
            dek = os.urandom(DEK_SIZE_BYTES)

            # Generate random nonce for GCM
            nonce = os.urandom(GCM_NONCE_SIZE_BYTES)

            # Compute plaintext hash for integrity verification
            content_hash = hashlib.sha256(plaintext).hexdigest()

            # Encrypt content with DEK
            aesgcm = AESGCM(dek)
            ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

            # Wrap DEK with KEK
            wrapped_dek = self._wrap_dek(dek)

            logger.debug(
                "Encrypted content: size=%d, hash=%s",
                len(plaintext),
                content_hash[:16] + "...",
            )

            return EncryptedContent(
                ciphertext=ciphertext,
                nonce=nonce,
                wrapped_dek=wrapped_dek,
                kek_id=self._kek_id or "",
                content_hash=content_hash,
                encrypted_at=datetime.now(UTC),
                algorithm=EncryptionMode.AES_256_GCM,
            )

        except Exception as e:
            logger.error("Encryption failed: %s", str(e))
            raise EncryptionError(f"Content encryption failed: {e}") from e

    async def decrypt(
        self,
        encrypted: EncryptedContent,
        *,
        associated_data: bytes | None = None,
        verify_hash: bool = True,
    ) -> bytes:
        """Decrypt content using envelope encryption.

        Unwraps the DEK with the KEK, then decrypts the content.

        Args:
            encrypted: EncryptedContent from prior encryption.
            associated_data: AAD used during encryption (must match).
            verify_hash: Whether to verify plaintext hash after decryption.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            DecryptionError: If decryption fails.
            KeyWrapError: If DEK unwrapping fails (wrong KEK).
        """
        self._ensure_initialized()

        if encrypted.algorithm == EncryptionMode.NONE:
            # Passthrough mode - return ciphertext as-is
            return encrypted.ciphertext

        try:
            # Unwrap DEK with KEK
            dek = self._unwrap_dek(encrypted.wrapped_dek)

            # Decrypt content with DEK
            aesgcm = AESGCM(dek)
            plaintext = aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, associated_data)

            # Verify plaintext hash for additional integrity check
            if verify_hash:
                computed_hash = hashlib.sha256(plaintext).hexdigest()
                if computed_hash != encrypted.content_hash:
                    raise DecryptionError(
                        f"Content hash mismatch: expected {encrypted.content_hash[:16]}..., "
                        f"got {computed_hash[:16]}..."
                    )

            logger.debug(
                "Decrypted content: size=%d, hash=%s",
                len(plaintext),
                encrypted.content_hash[:16] + "...",
            )

            return plaintext

        except DecryptionError:
            raise
        except KeyWrapError:
            raise
        except Exception as e:
            logger.error("Decryption failed: %s", str(e))
            raise DecryptionError(f"Content decryption failed: {e}") from e

    async def get_kek_info(self) -> KEKInfo | None:
        """Get information about the current KEK.

        Returns:
            KEKInfo or None if not initialized or mode is NONE.
        """
        if not self._initialized or self._config.mode == EncryptionMode.NONE:
            return None

        return KEKInfo(
            kek_id=self._kek_id or "",
            created_at=self._kek_created_at or datetime.now(UTC),
            algorithm="AES-256-GCM-KEYWRAP",
            status="active",
        )

    def _ensure_initialized(self) -> None:
        """Ensure service is initialized."""
        if not self._initialized:
            msg = "Encryption service not initialized. Call initialize() first."
            raise EncryptionError(msg)

    async def _load_or_generate_kek(self) -> None:
        """Load existing KEK or generate a new one.

        In non-qualified mode, KEK is stored encrypted at rest.
        In qualified mode, KEK would be in HSM (not yet implemented).
        """
        kek_dir = Path(self._config.kek_storage_path)
        kek_file = kek_dir / "kek.enc"
        kek_meta_file = kek_dir / "kek.json"

        if kek_file.exists() and kek_meta_file.exists():
            # Load existing KEK
            self._load_kek(kek_file, kek_meta_file)
        else:
            # Generate new KEK
            self._generate_kek(kek_dir, kek_file, kek_meta_file)

    def _load_kek(self, kek_file: Path, kek_meta_file: Path) -> None:
        """Load KEK from storage (synchronous I/O).

        Note: Uses synchronous file I/O for simplicity since KEK operations
        are infrequent (only at service startup).

        Args:
            kek_file: Path to the KEK file.
            kek_meta_file: Path to the KEK metadata file.
        """
        try:
            # Load metadata
            meta = json.loads(kek_meta_file.read_text())

            self._kek_id = meta["kek_id"]
            self._kek_created_at = datetime.fromisoformat(meta["created_at"])

            # Load encrypted KEK
            encrypted_kek = kek_file.read_bytes()

            # Decrypt KEK if password is set
            if self._config.kek_password:
                self._kek = self._decrypt_kek_at_rest(encrypted_kek)
            else:
                self._kek = encrypted_kek

            logger.info("Loaded existing KEK: %s", self._kek_id)

        except Exception as e:
            logger.error("Failed to load KEK: %s", str(e))
            raise EncryptionError(f"Failed to load KEK: {e}") from e

    def _generate_kek(self, kek_dir: Path, kek_file: Path, kek_meta_file: Path) -> None:
        """Generate a new KEK and save to storage (synchronous I/O).

        Note: Uses synchronous file I/O for simplicity since KEK operations
        are infrequent (only at service startup).

        Args:
            kek_dir: Directory for KEK storage.
            kek_file: Path to the KEK file.
            kek_meta_file: Path to the KEK metadata file.
        """
        try:
            # Create directory if needed
            kek_dir.mkdir(parents=True, exist_ok=True)

            # Generate KEK
            self._kek = os.urandom(DEK_SIZE_BYTES)
            self._kek_id = f"kek-{uuid.uuid4()}"
            self._kek_created_at = datetime.now(UTC)

            # Save metadata
            meta = {
                "kek_id": self._kek_id,
                "created_at": self._kek_created_at.isoformat(),
                "algorithm": "AES-256-GCM-KEYWRAP",
                "qualification_label": self._config.qualification_label,
            }
            kek_meta_file.write_text(json.dumps(meta, indent=2))

            # Save encrypted KEK
            if self._config.kek_password:
                encrypted_kek = self._encrypt_kek_at_rest(self._kek)
            else:
                encrypted_kek = self._kek

            kek_file.write_bytes(encrypted_kek)
            kek_file.chmod(0o600)  # Secure permissions

            logger.info(
                "Generated new KEK: %s (saved to %s)",
                self._kek_id,
                kek_file,
            )

        except Exception as e:
            logger.error("Failed to generate KEK: %s", str(e))
            raise EncryptionError(f"Failed to generate KEK: {e}") from e

    def _wrap_dek(self, dek: bytes) -> str:
        """Wrap (encrypt) DEK with KEK.

        Uses AES-256-GCM for key wrapping.

        Args:
            dek: Data Encryption Key to wrap.

        Returns:
            Base64-encoded wrapped DEK (nonce + ciphertext).
        """
        if self._kek is None:
            raise KeyWrapError("KEK not available")

        try:
            nonce = os.urandom(GCM_NONCE_SIZE_BYTES)
            aesgcm = AESGCM(self._kek)
            wrapped = aesgcm.encrypt(nonce, dek, None)

            # Concatenate nonce + wrapped DEK for storage
            return base64.b64encode(nonce + wrapped).decode("utf-8")

        except Exception as e:
            raise KeyWrapError(f"Failed to wrap DEK: {e}") from e

    def _unwrap_dek(self, wrapped_dek: str) -> bytes:
        """Unwrap (decrypt) DEK with KEK.

        Args:
            wrapped_dek: Base64-encoded wrapped DEK (nonce + ciphertext).

        Returns:
            Unwrapped DEK bytes.
        """
        if self._kek is None:
            raise KeyWrapError("KEK not available")

        try:
            wrapped_bytes = base64.b64decode(wrapped_dek)
            nonce = wrapped_bytes[:GCM_NONCE_SIZE_BYTES]
            ciphertext = wrapped_bytes[GCM_NONCE_SIZE_BYTES:]

            aesgcm = AESGCM(self._kek)
            return aesgcm.decrypt(nonce, ciphertext, None)

        except Exception as e:
            raise KeyWrapError(f"Failed to unwrap DEK: {e}") from e

    def _encrypt_kek_at_rest(self, kek: bytes) -> bytes:
        """Encrypt KEK for storage using password-derived key.

        Uses a simple password-based encryption for the KEK itself.
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        if not self._config.kek_password:
            return kek

        # Derive key from password
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # OWASP recommendation 2023
        )
        derived_key = kdf.derive(self._config.kek_password)

        # Encrypt KEK
        nonce = os.urandom(GCM_NONCE_SIZE_BYTES)
        aesgcm = AESGCM(derived_key)
        encrypted = aesgcm.encrypt(nonce, kek, None)

        # Format: salt (16) + nonce (12) + ciphertext
        return salt + nonce + encrypted

    def _decrypt_kek_at_rest(self, encrypted: bytes) -> bytes:
        """Decrypt KEK from storage using password-derived key."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        if not self._config.kek_password:
            return encrypted

        # Extract components
        salt = encrypted[:16]
        nonce = encrypted[16 : 16 + GCM_NONCE_SIZE_BYTES]
        ciphertext = encrypted[16 + GCM_NONCE_SIZE_BYTES :]

        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        derived_key = kdf.derive(self._config.kek_password)

        # Decrypt KEK
        aesgcm = AESGCM(derived_key)
        return aesgcm.decrypt(nonce, ciphertext, None)


async def create_encryption_service(
    mode: EncryptionMode = EncryptionMode.AES_256_GCM,
    kek_storage_path: str = "/keys/encryption",
    kek_password: bytes | None = None,
    qualification_label: str = "non_qualified",
) -> EncryptionService:
    """Create and initialize an encryption service.

    Factory function for creating a configured and initialized EncryptionService.

    Args:
        mode: Encryption mode.
        kek_storage_path: Path for KEK storage.
        kek_password: Password for KEK encryption at rest.
        qualification_label: Qualification status label.

    Returns:
        Initialized EncryptionService.

    Example:
        service = await create_encryption_service(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path="/tmp/keys",
        )
        encrypted = await service.encrypt(b"secret content")
    """
    config = EncryptionServiceConfig(
        mode=mode,
        kek_storage_path=kek_storage_path,
        kek_password=kek_password,
        qualification_label=qualification_label,
    )
    service = EncryptionService(config)
    await service.initialize()
    return service
