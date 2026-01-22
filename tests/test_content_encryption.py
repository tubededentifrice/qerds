"""Tests for ContentEncryptionService authorization checks.

Covers REQ-E01 (content encryption at rest) and REQ-E02 (content access gating).

These tests verify:
- Content is encrypted before storage
- Only authorized users can decrypt content:
  - Sender can always decrypt their own content
  - Recipient can decrypt only after ACCEPTED or RECEIVED state
  - Other users cannot decrypt
"""

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from qerds.db.models.base import DeliveryState
from qerds.services.content_encryption import (
    RECIPIENT_DECRYPTION_STATES,
    ContentEncryptionService,
)
from qerds.services.encryption import (
    AuthorizationError,
    DecryptionError,
    EncryptionMode,
)

# ---------------------------------------------------------------------------
# Mock Objects for Testing
# ---------------------------------------------------------------------------


@dataclass
class MockAuthenticatedUser:
    """Mock AuthenticatedUser for testing authorization.

    Mimics the AuthenticatedUser from qerds.api.middleware.auth.
    """

    principal_id: UUID
    principal_type: str = "party"
    session_id: UUID | None = None
    is_superuser: bool = False
    is_active: bool = True
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)
    ip_address: str | None = None
    user_agent: str | None = None
    auth_method: str = "session"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MockContentObject:
    """Mock content object for testing."""

    content_object_id: UUID


@dataclass
class MockDelivery:
    """Mock Delivery object for testing authorization.

    Provides minimal fields needed for content encryption authorization.
    """

    delivery_id: UUID
    sender_party_id: UUID
    recipient_party_id: UUID
    state: DeliveryState
    content_objects: list[MockContentObject] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_kek_dir():
    """Create a temporary directory for KEK storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def content_encryption_service(temp_kek_dir):
    """Create and initialize a ContentEncryptionService for tests."""
    service = await ContentEncryptionService.create(
        mode=EncryptionMode.AES_256_GCM,
        kek_storage_path=str(temp_kek_dir),
    )
    return service


@pytest.fixture
def test_content():
    """Sample content for encryption tests."""
    return b"Confidential delivery content - REQ-E01 compliance test"


@pytest.fixture
def sender_party_id():
    """UUID for the sender party."""
    return uuid4()


@pytest.fixture
def recipient_party_id():
    """UUID for the recipient party."""
    return uuid4()


@pytest.fixture
def third_party_id():
    """UUID for a third party (neither sender nor recipient)."""
    return uuid4()


@pytest.fixture
def delivery_id():
    """UUID for the delivery."""
    return uuid4()


@pytest.fixture
def content_object_id():
    """UUID for the content object."""
    return uuid4()


# ---------------------------------------------------------------------------
# REQ-E01: Content Encryption at Rest Tests
# ---------------------------------------------------------------------------


class TestContentEncryptionAtRest:
    """Tests for REQ-E01: content encryption before storage."""

    async def test_encrypt_for_storage_encrypts_content(
        self,
        content_encryption_service,
        test_content,
        delivery_id,
        content_object_id,
    ):
        """Test that content is encrypted before storage."""
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Ciphertext must differ from plaintext
        assert ciphertext != test_content

        # Ciphertext should be larger due to GCM auth tag
        assert len(ciphertext) > len(test_content)

        # Metadata should contain encryption details
        assert "version" in metadata
        assert "algorithm" in metadata
        assert "nonce" in metadata
        assert "wrapped_dek" in metadata
        assert "kek_id" in metadata
        assert "content_hash" in metadata
        assert "encrypted_at" in metadata

        assert metadata["algorithm"] == "aes_256_gcm"

    async def test_encrypted_content_not_readable_as_plaintext(
        self,
        content_encryption_service,
        test_content,
        delivery_id,
        content_object_id,
    ):
        """Test that encrypted content cannot be read without decryption."""
        ciphertext, _metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # The ciphertext should not contain the original text
        assert test_content not in ciphertext

        # Attempting to decode as UTF-8 should either fail or produce garbage
        try:
            decoded = ciphertext.decode("utf-8")
            # If it decodes, it should not be the original content
            assert decoded != test_content.decode("utf-8")
        except UnicodeDecodeError:
            # Expected - ciphertext is not valid UTF-8
            pass

    async def test_different_content_produces_different_ciphertext(
        self,
        content_encryption_service,
        delivery_id,
        content_object_id,
    ):
        """Test that different content produces different ciphertext."""
        content1 = b"First document content"
        content2 = b"Second document content"

        ciphertext1, _meta1 = await content_encryption_service.encrypt_for_storage(
            content=content1,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        ciphertext2, _meta2 = await content_encryption_service.encrypt_for_storage(
            content=content2,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        assert ciphertext1 != ciphertext2


# ---------------------------------------------------------------------------
# REQ-E02: Content Access Gating Tests
# ---------------------------------------------------------------------------


class TestContentAccessGating:
    """Tests for REQ-E02: content access gating via authorization."""

    async def test_sender_can_decrypt_own_content(
        self,
        content_encryption_service,
        test_content,
        sender_party_id,
        recipient_party_id,
        delivery_id,
        content_object_id,
    ):
        """Test that sender can always decrypt their own content (REQ-E02)."""
        # Encrypt content
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Create sender user
        sender_user = MockAuthenticatedUser(principal_id=sender_party_id)

        # Create delivery in any state - sender should always have access
        for state in DeliveryState:
            delivery = MockDelivery(
                delivery_id=delivery_id,
                sender_party_id=sender_party_id,
                recipient_party_id=recipient_party_id,
                state=state,
                content_objects=[MockContentObject(content_object_id=content_object_id)],
            )

            # Sender should be able to decrypt
            plaintext = await content_encryption_service.decrypt_for_user(
                ciphertext=ciphertext,
                encryption_metadata=metadata,
                user=sender_user,
                delivery=delivery,
            )

            assert plaintext == test_content

    async def test_recipient_can_decrypt_after_acceptance(
        self,
        content_encryption_service,
        test_content,
        sender_party_id,
        recipient_party_id,
        delivery_id,
        content_object_id,
    ):
        """Test that recipient can decrypt after ACCEPTED state (REQ-E02)."""
        # Encrypt content
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Create recipient user
        recipient_user = MockAuthenticatedUser(principal_id=recipient_party_id)

        # Test all states where recipient can decrypt
        for state in RECIPIENT_DECRYPTION_STATES:
            delivery = MockDelivery(
                delivery_id=delivery_id,
                sender_party_id=sender_party_id,
                recipient_party_id=recipient_party_id,
                state=state,
                content_objects=[MockContentObject(content_object_id=content_object_id)],
            )

            plaintext = await content_encryption_service.decrypt_for_user(
                ciphertext=ciphertext,
                encryption_metadata=metadata,
                user=recipient_user,
                delivery=delivery,
            )

            assert plaintext == test_content

    async def test_recipient_cannot_decrypt_before_acceptance(
        self,
        content_encryption_service,
        test_content,
        sender_party_id,
        recipient_party_id,
        delivery_id,
        content_object_id,
    ):
        """Test that recipient cannot decrypt before acceptance (REQ-E02, REQ-F03)."""
        # Encrypt content
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Create recipient user
        recipient_user = MockAuthenticatedUser(principal_id=recipient_party_id)

        # States where recipient should NOT have access
        unauthorized_states = [
            DeliveryState.DRAFT,
            DeliveryState.DEPOSITED,
            DeliveryState.NOTIFIED,
            DeliveryState.NOTIFICATION_FAILED,
            DeliveryState.AVAILABLE,
            DeliveryState.REFUSED,
            DeliveryState.EXPIRED,
        ]

        for state in unauthorized_states:
            delivery = MockDelivery(
                delivery_id=delivery_id,
                sender_party_id=sender_party_id,
                recipient_party_id=recipient_party_id,
                state=state,
                content_objects=[MockContentObject(content_object_id=content_object_id)],
            )

            with pytest.raises(AuthorizationError) as exc_info:
                await content_encryption_service.decrypt_for_user(
                    ciphertext=ciphertext,
                    encryption_metadata=metadata,
                    user=recipient_user,
                    delivery=delivery,
                )

            # Error message should indicate the issue
            assert (
                "not authorized" in str(exc_info.value).lower()
                or "state" in str(exc_info.value).lower()
            )

    async def test_third_party_cannot_decrypt(
        self,
        content_encryption_service,
        test_content,
        sender_party_id,
        recipient_party_id,
        third_party_id,
        delivery_id,
        content_object_id,
    ):
        """Test that third parties cannot decrypt content (REQ-E02)."""
        # Encrypt content
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Create third party user (neither sender nor recipient)
        third_party_user = MockAuthenticatedUser(principal_id=third_party_id)

        # Create delivery in ACCEPTED state (most permissive for recipient)
        delivery = MockDelivery(
            delivery_id=delivery_id,
            sender_party_id=sender_party_id,
            recipient_party_id=recipient_party_id,
            state=DeliveryState.ACCEPTED,
            content_objects=[MockContentObject(content_object_id=content_object_id)],
        )

        with pytest.raises(AuthorizationError) as exc_info:
            await content_encryption_service.decrypt_for_user(
                ciphertext=ciphertext,
                encryption_metadata=metadata,
                user=third_party_user,
                delivery=delivery,
            )

        assert "not authorized" in str(exc_info.value).lower()

    async def test_admin_cannot_decrypt_without_authorization(
        self,
        content_encryption_service,
        test_content,
        sender_party_id,
        recipient_party_id,
        delivery_id,
        content_object_id,
    ):
        """Test that admin users cannot decrypt without being sender/recipient (REQ-E01)."""
        # Encrypt content
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Create admin user (different principal_id than sender/recipient)
        admin_user = MockAuthenticatedUser(
            principal_id=uuid4(),
            principal_type="admin_user",
            is_superuser=True,
            roles=frozenset(["admin"]),
        )

        delivery = MockDelivery(
            delivery_id=delivery_id,
            sender_party_id=sender_party_id,
            recipient_party_id=recipient_party_id,
            state=DeliveryState.ACCEPTED,
            content_objects=[MockContentObject(content_object_id=content_object_id)],
        )

        # Even superusers should not be able to decrypt arbitrary content
        # Per REQ-E01: confidentiality against unauthorized access including operators
        with pytest.raises(AuthorizationError):
            await content_encryption_service.decrypt_for_user(
                ciphertext=ciphertext,
                encryption_metadata=metadata,
                user=admin_user,
                delivery=delivery,
            )


# ---------------------------------------------------------------------------
# AAD Binding Tests
# ---------------------------------------------------------------------------


class TestAADBinding:
    """Tests for AAD (Associated Authenticated Data) binding."""

    async def test_ciphertext_bound_to_delivery(
        self,
        content_encryption_service,
        test_content,
        sender_party_id,
        recipient_party_id,
        content_object_id,
    ):
        """Test that ciphertext is bound to specific delivery via AAD."""
        delivery_id_1 = uuid4()
        delivery_id_2 = uuid4()

        # Encrypt for delivery 1
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id_1,
            content_object_id=content_object_id,
        )

        # Try to decrypt with different delivery ID should fail
        with pytest.raises(DecryptionError):
            await content_encryption_service.decrypt_content_object(
                ciphertext=ciphertext,
                encryption_metadata=metadata,
                delivery_id=delivery_id_2,  # Wrong delivery ID
                content_object_id=content_object_id,
            )

    async def test_ciphertext_bound_to_content_object(
        self,
        content_encryption_service,
        test_content,
        delivery_id,
    ):
        """Test that ciphertext is bound to specific content object via AAD."""
        content_object_id_1 = uuid4()
        content_object_id_2 = uuid4()

        # Encrypt for content object 1
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id_1,
        )

        # Try to decrypt with different content object ID should fail
        with pytest.raises(DecryptionError):
            await content_encryption_service.decrypt_content_object(
                ciphertext=ciphertext,
                encryption_metadata=metadata,
                delivery_id=delivery_id,
                content_object_id=content_object_id_2,  # Wrong content object ID
            )


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestEncryptDecryptRoundtrip:
    """Integration tests for full encrypt/decrypt roundtrip."""

    async def test_full_workflow_sender_access(
        self,
        content_encryption_service,
        sender_party_id,
        recipient_party_id,
    ):
        """Test complete workflow: encrypt -> store -> retrieve -> decrypt for sender."""
        # Simulate realistic content
        content = b"PDF document content for registered delivery"
        delivery_id = uuid4()
        content_object_id = uuid4()

        # Step 1: Encrypt for storage
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Step 2: Create delivery and user context
        sender_user = MockAuthenticatedUser(principal_id=sender_party_id)
        delivery = MockDelivery(
            delivery_id=delivery_id,
            sender_party_id=sender_party_id,
            recipient_party_id=recipient_party_id,
            state=DeliveryState.DEPOSITED,
            content_objects=[MockContentObject(content_object_id=content_object_id)],
        )

        # Step 3: Decrypt for authorized user
        plaintext = await content_encryption_service.decrypt_for_user(
            ciphertext=ciphertext,
            encryption_metadata=metadata,
            user=sender_user,
            delivery=delivery,
        )

        assert plaintext == content

    async def test_full_workflow_recipient_access_after_accept(
        self,
        content_encryption_service,
        sender_party_id,
        recipient_party_id,
    ):
        """Test complete workflow for recipient after acceptance."""
        content = b"Important legal notice content"
        delivery_id = uuid4()
        content_object_id = uuid4()

        # Encrypt
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Create recipient user
        recipient_user = MockAuthenticatedUser(principal_id=recipient_party_id)

        # Delivery transitions to ACCEPTED
        delivery = MockDelivery(
            delivery_id=delivery_id,
            sender_party_id=sender_party_id,
            recipient_party_id=recipient_party_id,
            state=DeliveryState.ACCEPTED,
            content_objects=[MockContentObject(content_object_id=content_object_id)],
        )

        # Recipient can now decrypt
        plaintext = await content_encryption_service.decrypt_for_user(
            ciphertext=ciphertext,
            encryption_metadata=metadata,
            user=recipient_user,
            delivery=delivery,
        )

        assert plaintext == content

    async def test_large_content_handling(
        self,
        content_encryption_service,
        sender_party_id,
        recipient_party_id,
    ):
        """Test encryption/decryption of large content (1MB)."""
        # 1MB of content
        large_content = b"X" * (1024 * 1024)
        delivery_id = uuid4()
        content_object_id = uuid4()

        # Encrypt
        ciphertext, metadata = await content_encryption_service.encrypt_for_storage(
            content=large_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Create authorized user and delivery
        sender_user = MockAuthenticatedUser(principal_id=sender_party_id)
        delivery = MockDelivery(
            delivery_id=delivery_id,
            sender_party_id=sender_party_id,
            recipient_party_id=recipient_party_id,
            state=DeliveryState.DEPOSITED,
            content_objects=[MockContentObject(content_object_id=content_object_id)],
        )

        # Decrypt
        plaintext = await content_encryption_service.decrypt_for_user(
            ciphertext=ciphertext,
            encryption_metadata=metadata,
            user=sender_user,
            delivery=delivery,
        )

        assert plaintext == large_content
