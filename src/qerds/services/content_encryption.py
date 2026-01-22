"""Content encryption integration for delivery content objects.

Covers: REQ-E01 (content encryption at rest), REQ-E02 (content access gating)

This module provides high-level integration between the encryption service
and the delivery content workflow:
- Encrypts content on upload (before storage)
- Decrypts content for authorized sessions (sender or accepted recipient)
- Manages encryption metadata persistence

Authorization Model (REQ-E02):
- Sender: Can always decrypt their own content
- Recipient: Can decrypt only after ACCEPTED or RECEIVED state
- Admin: Cannot decrypt without proper authorization context

Example:
    from qerds.services.content_encryption import ContentEncryptionService

    service = await ContentEncryptionService.create()

    # Encrypt on upload
    encrypted, metadata = await service.encrypt_for_storage(
        content=file_bytes,
        delivery_id=delivery_id,
        content_object_id=content_id,
    )
    # Store encrypted content and metadata

    # Decrypt for authorized user
    plaintext = await service.decrypt_for_user(
        ciphertext=encrypted_bytes,
        encryption_metadata=metadata_dict,
        user=authenticated_user,
        delivery=delivery_obj,
    )
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from uuid import UUID

from qerds.db.models.base import DeliveryState
from qerds.services.encryption import (
    AuthorizationError,
    DecryptionError,
    EncryptedContent,
    EncryptionError,
    EncryptionMode,
    EncryptionService,
    EncryptionServiceConfig,
)

if TYPE_CHECKING:
    from qerds.api.middleware.auth import AuthenticatedUser
    from qerds.db.models.deliveries import Delivery

logger = logging.getLogger(__name__)


# States where recipient is authorized to decrypt content
RECIPIENT_DECRYPTION_STATES = frozenset(
    {
        DeliveryState.ACCEPTED,
        DeliveryState.RECEIVED,
    }
)


class ContentEncryptionService:
    """High-level service for content encryption in delivery workflows.

    Wraps the low-level EncryptionService with delivery-specific logic:
    - AAD (Associated Authenticated Data) includes delivery context
    - Authorization checks for decryption
    - Metadata management for content objects

    Per REQ-E01, all content must be encrypted at rest.
    Per REQ-E02, decryption is gated by authorization rules.
    """

    def __init__(self, encryption_service: EncryptionService) -> None:
        """Initialize with an underlying encryption service.

        Args:
            encryption_service: Initialized EncryptionService instance.
        """
        self._encryption = encryption_service

    @classmethod
    async def create(
        cls,
        mode: EncryptionMode = EncryptionMode.AES_256_GCM,
        kek_storage_path: str = "/keys/encryption",
        kek_password: bytes | None = None,
    ) -> ContentEncryptionService:
        """Factory method to create and initialize the service.

        Args:
            mode: Encryption mode.
            kek_storage_path: Path for KEK storage.
            kek_password: Password for KEK encryption at rest.

        Returns:
            Initialized ContentEncryptionService.
        """
        config = EncryptionServiceConfig(
            mode=mode,
            kek_storage_path=kek_storage_path,
            kek_password=kek_password,
        )
        encryption_service = EncryptionService(config)
        await encryption_service.initialize()
        return cls(encryption_service)

    @property
    def is_encryption_enabled(self) -> bool:
        """Check if encryption is enabled."""
        return self._encryption.is_encryption_enabled

    async def encrypt_for_storage(
        self,
        content: bytes,
        delivery_id: UUID,
        content_object_id: UUID,
    ) -> tuple[bytes, dict[str, Any]]:
        """Encrypt content for storage in the object store.

        Encrypts the content using envelope encryption and returns both
        the ciphertext and the encryption metadata for database storage.

        The AAD includes delivery and content identifiers to bind the
        encryption to specific objects, preventing ciphertext reuse.

        Args:
            content: Plaintext content bytes.
            delivery_id: UUID of the delivery.
            content_object_id: UUID of the content object.

        Returns:
            Tuple of (ciphertext bytes, encryption metadata dict).

        Raises:
            EncryptionError: If encryption fails.
        """
        # Build AAD (Associated Authenticated Data)
        # This binds the ciphertext to the specific delivery and content object
        aad = self._build_aad(delivery_id, content_object_id)

        try:
            encrypted = await self._encryption.encrypt(content, associated_data=aad)

            logger.info(
                "Encrypted content for storage: delivery=%s, content=%s, size=%d",
                delivery_id,
                content_object_id,
                len(content),
            )

            return encrypted.ciphertext, encrypted.to_metadata_dict()

        except EncryptionError:
            raise
        except Exception as e:
            logger.error(
                "Content encryption failed: delivery=%s, error=%s",
                delivery_id,
                str(e),
            )
            raise EncryptionError(f"Failed to encrypt content: {e}") from e

    async def decrypt_for_user(
        self,
        ciphertext: bytes,
        encryption_metadata: dict[str, Any],
        user: AuthenticatedUser,
        delivery: Delivery,
    ) -> bytes:
        """Decrypt content for an authorized user.

        Checks authorization before decrypting:
        - Sender can always decrypt their own content
        - Recipient can decrypt after acceptance

        Args:
            ciphertext: Encrypted content bytes.
            encryption_metadata: Encryption metadata from database.
            user: Authenticated user requesting decryption.
            delivery: The delivery containing the content.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthorizationError: If user is not authorized to decrypt.
            DecryptionError: If decryption fails.
        """
        # Check authorization
        self._check_decryption_authorization(user, delivery)

        # Get content object ID from delivery for AAD reconstruction
        # For now, use the delivery ID - in practice, this should come from the content object
        content_object_id = UUID(int=0)  # Placeholder - should be passed in
        if delivery.content_objects:
            # Find the matching content object by checking the storage key or hash
            # For now, use the first one's ID as a fallback
            content_object_id = delivery.content_objects[0].content_object_id

        # Rebuild AAD for authenticated decryption
        aad = self._build_aad(delivery.delivery_id, content_object_id)

        try:
            # Reconstruct EncryptedContent from metadata
            encrypted = EncryptedContent.from_metadata_dict(encryption_metadata, ciphertext)

            plaintext = await self._encryption.decrypt(encrypted, associated_data=aad)

            logger.info(
                "Decrypted content for user: delivery=%s, user=%s",
                delivery.delivery_id,
                user.principal_id,
            )

            return plaintext

        except DecryptionError:
            raise
        except Exception as e:
            logger.error(
                "Content decryption failed: delivery=%s, error=%s",
                delivery.delivery_id,
                str(e),
            )
            raise DecryptionError(f"Failed to decrypt content: {e}") from e

    async def decrypt_content_object(
        self,
        ciphertext: bytes,
        encryption_metadata: dict[str, Any],
        delivery_id: UUID,
        content_object_id: UUID,
    ) -> bytes:
        """Decrypt a content object without authorization check.

        Use this method only when authorization has been verified externally.
        For user-facing decryption, use decrypt_for_user().

        Args:
            ciphertext: Encrypted content bytes.
            encryption_metadata: Encryption metadata from database.
            delivery_id: UUID of the delivery.
            content_object_id: UUID of the content object.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            DecryptionError: If decryption fails.
        """
        aad = self._build_aad(delivery_id, content_object_id)

        try:
            encrypted = EncryptedContent.from_metadata_dict(encryption_metadata, ciphertext)
            return await self._encryption.decrypt(encrypted, associated_data=aad)
        except Exception as e:
            raise DecryptionError(f"Failed to decrypt content: {e}") from e

    def _build_aad(self, delivery_id: UUID, content_object_id: UUID) -> bytes:
        """Build Associated Authenticated Data for AEAD.

        The AAD binds the ciphertext to the specific delivery and content,
        preventing ciphertext from being moved between objects.

        Args:
            delivery_id: Delivery UUID.
            content_object_id: Content object UUID.

        Returns:
            AAD bytes.
        """
        # Deterministic AAD format: delivery_id|content_object_id
        return f"{delivery_id}|{content_object_id}".encode()

    def _check_decryption_authorization(
        self,
        user: AuthenticatedUser,
        delivery: Delivery,
    ) -> None:
        """Check if user is authorized to decrypt delivery content.

        Authorization rules (REQ-E02):
        1. Sender can always decrypt their own content
        2. Recipient can decrypt after acceptance (ACCEPTED or RECEIVED state)
        3. Admin cannot decrypt without special authorization

        Args:
            user: Authenticated user.
            delivery: The delivery.

        Raises:
            AuthorizationError: If not authorized.
        """
        # Check if user is the sender
        if user.principal_id == delivery.sender_party_id:
            logger.debug(
                "Decryption authorized: user is sender: delivery=%s",
                delivery.delivery_id,
            )
            return

        # Check if user is the recipient with appropriate state
        if user.principal_id == delivery.recipient_party_id:
            if delivery.state in RECIPIENT_DECRYPTION_STATES:
                logger.debug(
                    "Decryption authorized: recipient in state %s: delivery=%s",
                    delivery.state.value,
                    delivery.delivery_id,
                )
                return
            else:
                raise AuthorizationError(
                    f"Recipient not authorized: delivery in {delivery.state.value} state. "
                    "Content access requires ACCEPTED or RECEIVED state."
                )

        # User is neither sender nor recipient
        logger.warning(
            "Decryption denied: user %s not authorized for delivery %s",
            user.principal_id,
            delivery.delivery_id,
        )
        raise AuthorizationError(
            "Not authorized to decrypt this content. "
            "Only the sender or an accepted recipient can access content."
        )


# Module-level singleton for the content encryption service
_content_encryption_service: ContentEncryptionService | None = None


async def get_content_encryption_service() -> ContentEncryptionService:
    """Get or create the content encryption service singleton.

    Returns:
        Initialized ContentEncryptionService.
    """
    global _content_encryption_service
    if _content_encryption_service is None:
        import os

        mode_str = os.environ.get("QERDS_ENCRYPTION_MODE", "aes_256_gcm")
        mode = EncryptionMode(mode_str)
        kek_path = os.environ.get("QERDS_KEK_STORAGE", "/keys/encryption")
        kek_password_str = os.environ.get("QERDS_KEK_PASSWORD", "")
        kek_password = kek_password_str.encode("utf-8") if kek_password_str else None

        _content_encryption_service = await ContentEncryptionService.create(
            mode=mode,
            kek_storage_path=kek_path,
            kek_password=kek_password,
        )

    return _content_encryption_service


def set_content_encryption_service_for_testing(service: ContentEncryptionService) -> None:
    """Set the content encryption service for testing.

    Args:
        service: Service instance to use.
    """
    global _content_encryption_service
    _content_encryption_service = service


def clear_content_encryption_service() -> None:
    """Clear the content encryption service singleton.

    Use in tests to reset between test cases.
    """
    global _content_encryption_service
    _content_encryption_service = None
