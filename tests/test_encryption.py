"""Tests for the encryption service.

Covers REQ-E01 (content encryption at rest) and REQ-E02 (content access gating).
Tests run against the EncryptionService and ContentEncryptionService classes.
"""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from qerds.services.encryption import (
    DecryptionError,
    EncryptedContent,
    EncryptionError,
    EncryptionMode,
    EncryptionService,
    EncryptionServiceConfig,
    KeyWrapError,
    create_encryption_service,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_kek_dir():
    """Create a temporary directory for KEK storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def encryption_config(temp_kek_dir):
    """Create a test encryption service configuration."""
    return EncryptionServiceConfig(
        mode=EncryptionMode.AES_256_GCM,
        kek_storage_path=str(temp_kek_dir),
        kek_password=None,  # No password in tests for simplicity
        qualification_label="non_qualified",
    )


@pytest.fixture
async def encryption_service(encryption_config):
    """Create and initialize an encryption service for tests."""
    service = EncryptionService(encryption_config)
    await service.initialize()
    return service


@pytest.fixture
def test_content():
    """Sample content for encryption tests."""
    return b"Test content for QERDS encryption service - REQ-E01"


@pytest.fixture
def large_content():
    """Large content for encryption tests (1MB)."""
    return b"X" * (1024 * 1024)


# ---------------------------------------------------------------------------
# EncryptionServiceConfig Tests
# ---------------------------------------------------------------------------


class TestEncryptionServiceConfig:
    """Tests for EncryptionServiceConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = EncryptionServiceConfig()
        assert config.mode == EncryptionMode.AES_256_GCM
        assert config.kek_storage_path == "/keys/encryption"
        assert config.kek_password is None
        assert config.qualification_label == "non_qualified"

    def test_custom_config(self, temp_kek_dir):
        """Test custom configuration."""
        config = EncryptionServiceConfig(
            mode=EncryptionMode.NONE,
            kek_storage_path=str(temp_kek_dir),
            kek_password=b"test-password",
            qualification_label="qualified",
        )
        assert config.mode == EncryptionMode.NONE
        assert config.kek_storage_path == str(temp_kek_dir)
        assert config.kek_password == b"test-password"


# ---------------------------------------------------------------------------
# EncryptionService Initialization Tests
# ---------------------------------------------------------------------------


class TestEncryptionServiceInitialization:
    """Tests for EncryptionService initialization."""

    async def test_initialize_creates_kek(self, encryption_config):
        """Test that KEK is created on initialization."""
        service = EncryptionService(encryption_config)
        await service.initialize()

        kek_info = await service.get_kek_info()
        assert kek_info is not None
        assert kek_info.kek_id.startswith("kek-")
        assert kek_info.status == "active"

    async def test_initialize_loads_existing_kek(self, encryption_config):
        """Test that existing KEK is loaded on subsequent inits."""
        # First init - creates KEK
        service1 = EncryptionService(encryption_config)
        await service1.initialize()
        kek_info1 = await service1.get_kek_info()

        # Second init - loads existing KEK
        service2 = EncryptionService(encryption_config)
        await service2.initialize()
        kek_info2 = await service2.get_kek_info()

        # KEK ID should be the same
        assert kek_info1.kek_id == kek_info2.kek_id

    async def test_initialize_none_mode(self, temp_kek_dir):
        """Test initialization in NONE mode (no encryption)."""
        config = EncryptionServiceConfig(
            mode=EncryptionMode.NONE,
            kek_storage_path=str(temp_kek_dir),
        )
        service = EncryptionService(config)
        await service.initialize()

        assert not service.is_encryption_enabled
        kek_info = await service.get_kek_info()
        assert kek_info is None

    async def test_operations_before_init_fail(self, encryption_config):
        """Test that operations fail before initialization."""
        service = EncryptionService(encryption_config)

        with pytest.raises(EncryptionError, match="not initialized"):
            await service.encrypt(b"data")


# ---------------------------------------------------------------------------
# Encryption Tests
# ---------------------------------------------------------------------------


class TestEncryption:
    """Tests for content encryption operations."""

    async def test_encrypt_basic(self, encryption_service, test_content):
        """Test basic encryption operation."""
        encrypted = await encryption_service.encrypt(test_content)

        assert encrypted.ciphertext != test_content
        assert len(encrypted.ciphertext) > len(test_content)  # GCM adds auth tag
        assert len(encrypted.nonce) == 12  # GCM nonce size
        assert encrypted.wrapped_dek  # DEK is wrapped
        assert encrypted.kek_id.startswith("kek-")
        assert encrypted.algorithm == EncryptionMode.AES_256_GCM
        assert encrypted.content_hash  # SHA-256 of plaintext

    async def test_encrypt_different_content_different_ciphertext(self, encryption_service):
        """Test that different content produces different ciphertext."""
        encrypted1 = await encryption_service.encrypt(b"content one")
        encrypted2 = await encryption_service.encrypt(b"content two")

        assert encrypted1.ciphertext != encrypted2.ciphertext
        assert encrypted1.wrapped_dek != encrypted2.wrapped_dek  # Different DEKs
        assert encrypted1.content_hash != encrypted2.content_hash

    async def test_encrypt_same_content_different_ciphertext(
        self, encryption_service, test_content
    ):
        """Test that same content produces different ciphertext (nonce randomness)."""
        encrypted1 = await encryption_service.encrypt(test_content)
        encrypted2 = await encryption_service.encrypt(test_content)

        # Ciphertext should differ due to random nonce
        assert encrypted1.ciphertext != encrypted2.ciphertext
        assert encrypted1.nonce != encrypted2.nonce

        # But content hash should be same
        assert encrypted1.content_hash == encrypted2.content_hash

    async def test_encrypt_with_aad(self, encryption_service, test_content):
        """Test encryption with associated authenticated data."""
        aad = b"delivery-123|content-456"
        encrypted = await encryption_service.encrypt(test_content, associated_data=aad)

        assert encrypted.ciphertext != test_content

    async def test_encrypt_large_content(self, encryption_service, large_content):
        """Test encryption of large content (1MB)."""
        encrypted = await encryption_service.encrypt(large_content)

        assert len(encrypted.ciphertext) >= len(large_content)

    async def test_encrypt_empty_content(self, encryption_service):
        """Test encryption of empty content."""
        encrypted = await encryption_service.encrypt(b"")

        # GCM can encrypt empty data (produces just auth tag)
        assert len(encrypted.ciphertext) == 16  # Just the GCM tag

    async def test_encrypt_none_mode_passthrough(self, temp_kek_dir, test_content):
        """Test that NONE mode passes through without encryption."""
        config = EncryptionServiceConfig(
            mode=EncryptionMode.NONE,
            kek_storage_path=str(temp_kek_dir),
        )
        service = EncryptionService(config)
        await service.initialize()

        encrypted = await service.encrypt(test_content)

        # In NONE mode, ciphertext equals plaintext
        assert encrypted.ciphertext == test_content
        assert encrypted.algorithm == EncryptionMode.NONE
        assert encrypted.wrapped_dek == ""


# ---------------------------------------------------------------------------
# Decryption Tests
# ---------------------------------------------------------------------------


class TestDecryption:
    """Tests for content decryption operations."""

    async def test_decrypt_basic(self, encryption_service, test_content):
        """Test basic decryption operation."""
        encrypted = await encryption_service.encrypt(test_content)
        decrypted = await encryption_service.decrypt(encrypted)

        assert decrypted == test_content

    async def test_decrypt_with_aad(self, encryption_service, test_content):
        """Test decryption with associated authenticated data."""
        aad = b"delivery-123|content-456"
        encrypted = await encryption_service.encrypt(test_content, associated_data=aad)
        decrypted = await encryption_service.decrypt(encrypted, associated_data=aad)

        assert decrypted == test_content

    async def test_decrypt_wrong_aad_fails(self, encryption_service, test_content):
        """Test that decryption fails with wrong AAD."""
        aad = b"delivery-123|content-456"
        encrypted = await encryption_service.encrypt(test_content, associated_data=aad)

        with pytest.raises(DecryptionError):
            await encryption_service.decrypt(encrypted, associated_data=b"wrong-aad")

    async def test_decrypt_modified_ciphertext_fails(self, encryption_service, test_content):
        """Test that decryption fails with modified ciphertext (integrity)."""
        encrypted = await encryption_service.encrypt(test_content)

        # Modify ciphertext
        modified_ciphertext = bytes([encrypted.ciphertext[0] ^ 0xFF]) + encrypted.ciphertext[1:]
        modified = EncryptedContent(
            ciphertext=modified_ciphertext,
            nonce=encrypted.nonce,
            wrapped_dek=encrypted.wrapped_dek,
            kek_id=encrypted.kek_id,
            content_hash=encrypted.content_hash,
            encrypted_at=encrypted.encrypted_at,
            algorithm=encrypted.algorithm,
        )

        with pytest.raises(DecryptionError):
            await encryption_service.decrypt(modified)

    async def test_decrypt_wrong_kek_fails(self, temp_kek_dir, test_content):
        """Test that decryption fails with different KEK."""
        # Encrypt with first service
        config1 = EncryptionServiceConfig(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path=str(temp_kek_dir / "kek1"),
        )
        service1 = EncryptionService(config1)
        await service1.initialize()
        encrypted = await service1.encrypt(test_content)

        # Try to decrypt with second service (different KEK)
        config2 = EncryptionServiceConfig(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path=str(temp_kek_dir / "kek2"),
        )
        service2 = EncryptionService(config2)
        await service2.initialize()

        with pytest.raises(KeyWrapError):
            await service2.decrypt(encrypted)

    async def test_decrypt_verifies_hash(self, encryption_service, test_content):
        """Test that decryption verifies plaintext hash."""
        encrypted = await encryption_service.encrypt(test_content)

        # Corrupt the stored hash
        corrupted = EncryptedContent(
            ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            wrapped_dek=encrypted.wrapped_dek,
            kek_id=encrypted.kek_id,
            content_hash="0" * 64,  # Wrong hash
            encrypted_at=encrypted.encrypted_at,
            algorithm=encrypted.algorithm,
        )

        with pytest.raises(DecryptionError, match="hash mismatch"):
            await encryption_service.decrypt(corrupted, verify_hash=True)

    async def test_decrypt_skip_hash_verification(self, encryption_service, test_content):
        """Test decryption with hash verification disabled."""
        encrypted = await encryption_service.encrypt(test_content)

        # Corrupt the stored hash but disable verification
        corrupted = EncryptedContent(
            ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            wrapped_dek=encrypted.wrapped_dek,
            kek_id=encrypted.kek_id,
            content_hash="0" * 64,
            encrypted_at=encrypted.encrypted_at,
            algorithm=encrypted.algorithm,
        )

        # Should succeed without hash check
        decrypted = await encryption_service.decrypt(corrupted, verify_hash=False)
        assert decrypted == test_content

    async def test_decrypt_large_content(self, encryption_service, large_content):
        """Test decryption of large content."""
        encrypted = await encryption_service.encrypt(large_content)
        decrypted = await encryption_service.decrypt(encrypted)

        assert decrypted == large_content

    async def test_decrypt_none_mode_passthrough(self, temp_kek_dir, test_content):
        """Test that NONE mode decryption returns content as-is."""
        config = EncryptionServiceConfig(
            mode=EncryptionMode.NONE,
            kek_storage_path=str(temp_kek_dir),
        )
        service = EncryptionService(config)
        await service.initialize()

        encrypted = await service.encrypt(test_content)
        decrypted = await service.decrypt(encrypted)

        assert decrypted == test_content


# ---------------------------------------------------------------------------
# EncryptedContent Serialization Tests
# ---------------------------------------------------------------------------


class TestEncryptedContentSerialization:
    """Tests for EncryptedContent metadata serialization."""

    async def test_to_metadata_dict(self, encryption_service, test_content):
        """Test conversion to metadata dictionary."""
        encrypted = await encryption_service.encrypt(test_content)
        metadata = encrypted.to_metadata_dict()

        assert "version" in metadata
        assert "algorithm" in metadata
        assert "nonce" in metadata
        assert "wrapped_dek" in metadata
        assert "kek_id" in metadata
        assert "content_hash" in metadata
        assert "encrypted_at" in metadata

        assert metadata["version"] == "1.0"
        assert metadata["algorithm"] == "aes_256_gcm"

    async def test_from_metadata_dict(self, encryption_service, test_content):
        """Test reconstruction from metadata dictionary."""
        encrypted = await encryption_service.encrypt(test_content)
        metadata = encrypted.to_metadata_dict()

        # Reconstruct from metadata
        reconstructed = EncryptedContent.from_metadata_dict(
            metadata,
            encrypted.ciphertext,
        )

        assert reconstructed.nonce == encrypted.nonce
        assert reconstructed.wrapped_dek == encrypted.wrapped_dek
        assert reconstructed.kek_id == encrypted.kek_id
        assert reconstructed.content_hash == encrypted.content_hash
        assert reconstructed.algorithm == encrypted.algorithm

    async def test_roundtrip_via_metadata(self, encryption_service, test_content):
        """Test encrypt -> serialize -> deserialize -> decrypt roundtrip."""
        # Encrypt
        encrypted = await encryption_service.encrypt(test_content)

        # Serialize (what would be stored in database)
        metadata = encrypted.to_metadata_dict()
        ciphertext = encrypted.ciphertext

        # Deserialize (what would be loaded from database)
        loaded = EncryptedContent.from_metadata_dict(metadata, ciphertext)

        # Decrypt
        decrypted = await encryption_service.decrypt(loaded)

        assert decrypted == test_content


# ---------------------------------------------------------------------------
# KEK Management Tests
# ---------------------------------------------------------------------------


class TestKEKManagement:
    """Tests for Key Encryption Key management."""

    async def test_kek_info(self, encryption_service):
        """Test getting KEK information."""
        kek_info = await encryption_service.get_kek_info()

        assert kek_info.kek_id.startswith("kek-")
        assert kek_info.algorithm == "AES-256-GCM-KEYWRAP"
        assert kek_info.status == "active"
        assert kek_info.created_at <= datetime.now(UTC)

    async def test_kek_encrypted_with_password(self, temp_kek_dir):
        """Test that KEK is encrypted when password is provided."""
        config = EncryptionServiceConfig(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path=str(temp_kek_dir),
            kek_password=b"test-encryption-password",
        )
        service = EncryptionService(config)
        await service.initialize()

        # KEK file should be larger than 32 bytes (includes salt + nonce + ciphertext)
        kek_file = temp_kek_dir / "kek.enc"
        assert kek_file.exists()
        assert len(kek_file.read_bytes()) > 32  # Salt(16) + Nonce(12) + KEK(32) + Tag(16)

    async def test_kek_not_encrypted_without_password(self, temp_kek_dir):
        """Test that KEK is stored in plaintext without password."""
        config = EncryptionServiceConfig(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path=str(temp_kek_dir),
            kek_password=None,
        )
        service = EncryptionService(config)
        await service.initialize()

        # KEK file should be exactly 32 bytes (raw key)
        kek_file = temp_kek_dir / "kek.enc"
        assert kek_file.exists()
        assert len(kek_file.read_bytes()) == 32

    async def test_kek_persists_across_restarts(self, temp_kek_dir, test_content):
        """Test that KEK persists and works across service restarts."""
        config = EncryptionServiceConfig(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path=str(temp_kek_dir),
            kek_password=b"persist-test",
        )

        # First service instance - encrypt
        service1 = EncryptionService(config)
        await service1.initialize()
        encrypted = await service1.encrypt(test_content)

        # Simulate restart - new service instance with same config
        service2 = EncryptionService(config)
        await service2.initialize()
        decrypted = await service2.decrypt(encrypted)

        assert decrypted == test_content


# ---------------------------------------------------------------------------
# Factory Function Tests
# ---------------------------------------------------------------------------


class TestFactoryFunction:
    """Tests for create_encryption_service factory."""

    async def test_create_encryption_service(self, temp_kek_dir):
        """Test factory function creates initialized service."""
        service = await create_encryption_service(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path=str(temp_kek_dir),
        )

        assert service.is_encryption_enabled
        kek_info = await service.get_kek_info()
        assert kek_info is not None

    async def test_create_with_password(self, temp_kek_dir, test_content):
        """Test factory function with KEK password."""
        service = await create_encryption_service(
            mode=EncryptionMode.AES_256_GCM,
            kek_storage_path=str(temp_kek_dir),
            kek_password=b"test-password",
        )

        # Verify encryption works
        encrypted = await service.encrypt(test_content)
        decrypted = await service.decrypt(encrypted)
        assert decrypted == test_content


# ---------------------------------------------------------------------------
# Content Encryption Service Tests (High-Level Integration)
# ---------------------------------------------------------------------------


class TestContentEncryptionService:
    """Tests for the high-level ContentEncryptionService."""

    async def test_encrypt_for_storage(self, temp_kek_dir, test_content):
        """Test encrypting content for storage."""
        from qerds.services.content_encryption import ContentEncryptionService

        service = await ContentEncryptionService.create(
            kek_storage_path=str(temp_kek_dir),
        )

        delivery_id = uuid4()
        content_object_id = uuid4()

        ciphertext, metadata = await service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        assert ciphertext != test_content
        assert "version" in metadata
        assert "wrapped_dek" in metadata
        assert "kek_id" in metadata

    async def test_decrypt_content_object(self, temp_kek_dir, test_content):
        """Test decrypting a content object."""
        from qerds.services.content_encryption import ContentEncryptionService

        service = await ContentEncryptionService.create(
            kek_storage_path=str(temp_kek_dir),
        )

        delivery_id = uuid4()
        content_object_id = uuid4()

        # Encrypt
        ciphertext, metadata = await service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Decrypt
        plaintext = await service.decrypt_content_object(
            ciphertext=ciphertext,
            encryption_metadata=metadata,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        assert plaintext == test_content

    async def test_aad_binding(self, temp_kek_dir, test_content):
        """Test that AAD binds ciphertext to specific delivery/content."""
        from qerds.services.content_encryption import ContentEncryptionService, DecryptionError

        service = await ContentEncryptionService.create(
            kek_storage_path=str(temp_kek_dir),
        )

        delivery_id = uuid4()
        content_object_id = uuid4()
        wrong_delivery_id = uuid4()

        # Encrypt with correct IDs
        ciphertext, metadata = await service.encrypt_for_storage(
            content=test_content,
            delivery_id=delivery_id,
            content_object_id=content_object_id,
        )

        # Attempt decrypt with wrong delivery ID should fail
        with pytest.raises(DecryptionError):
            await service.decrypt_content_object(
                ciphertext=ciphertext,
                encryption_metadata=metadata,
                delivery_id=wrong_delivery_id,  # Wrong ID
                content_object_id=content_object_id,
            )
