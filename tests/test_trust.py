"""Tests for the trust service.

Covers signing, sealing, timestamping, and key management operations.
Tests run against the TrustService class in non-qualified mode.
"""

import base64
import hashlib
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from httpx import ASGITransport, AsyncClient

from qerds.api.routers.trust import (
    get_trust_service_for_testing,
)
from qerds.api.routers.trust import (
    router as trust_router,
)
from qerds.services.trust import (
    AlgorithmSuite,
    DualControlRequiredError,
    DualControlSameUserError,
    KeyNotFoundError,
    KeyPurpose,
    KeyStatus,
    KeyStatusError,
    QualificationMode,
    QualifiedModeNotImplementedError,
    TrustService,
    TrustServiceConfig,
    TrustServiceError,
    create_trust_service,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_key_dir():
    """Create a temporary directory for key storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def trust_config(temp_key_dir):
    """Create a test trust service configuration."""
    return TrustServiceConfig(
        mode=QualificationMode.NON_QUALIFIED,
        key_storage_path=temp_key_dir,
        key_password=None,  # No encryption in tests for simplicity
        organization_name="QERDS Test",
        country="FR",
        policy_snapshot_id="test-policy-v1",
    )


@pytest.fixture
async def trust_service(trust_config):
    """Create and initialize a trust service for tests."""
    service = TrustService(trust_config)
    await service.initialize()
    return service


@pytest.fixture
def test_data():
    """Sample data for sealing and timestamping tests."""
    return b"Test evidence data for QERDS trust service"


@pytest.fixture
def test_data_b64(test_data):
    """Base64-encoded test data."""
    return base64.b64encode(test_data).decode("utf-8")


# ---------------------------------------------------------------------------
# TrustServiceConfig Tests
# ---------------------------------------------------------------------------


class TestTrustServiceConfig:
    """Tests for TrustServiceConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = TrustServiceConfig()
        assert config.mode == QualificationMode.NON_QUALIFIED
        assert config.key_storage_path == Path("/keys")
        assert config.key_password is None
        assert config.organization_name == "QERDS Development"
        assert config.country == "FR"
        assert config.policy_snapshot_id == "dev-policy-v1"

    def test_custom_config(self, temp_key_dir):
        """Test custom configuration."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            key_password=b"test-password",
            organization_name="Test Org",
            country="DE",
            policy_snapshot_id="custom-policy",
        )
        assert config.key_storage_path == temp_key_dir
        assert config.key_password == b"test-password"
        assert config.organization_name == "Test Org"
        assert config.country == "DE"


# ---------------------------------------------------------------------------
# AlgorithmSuite Tests
# ---------------------------------------------------------------------------


class TestAlgorithmSuite:
    """Tests for AlgorithmSuite."""

    def test_default_suite(self):
        """Test default algorithm suite."""
        suite = AlgorithmSuite.default()
        assert suite.version == "2026.1"
        assert suite.hash_algorithm == "sha384"
        assert suite.signature_algorithm == "ECDSA-P384"
        assert suite.key_size == 384

    def test_custom_suite(self):
        """Test custom algorithm suite."""
        suite = AlgorithmSuite(
            version="2025.1",
            hash_algorithm="sha256",
            signature_algorithm="ECDSA-P256",
            key_size=256,
        )
        assert suite.version == "2025.1"
        assert suite.hash_algorithm == "sha256"

    def test_suite_immutable(self):
        """Test that AlgorithmSuite is immutable."""
        suite = AlgorithmSuite.default()
        with pytest.raises(AttributeError):
            suite.version = "modified"


# ---------------------------------------------------------------------------
# TrustService Initialization Tests
# ---------------------------------------------------------------------------


class TestTrustServiceInitialization:
    """Tests for TrustService initialization."""

    async def test_initialize_non_qualified(self, trust_config):
        """Test initialization in non-qualified mode."""
        service = TrustService(trust_config)
        await service.initialize()

        assert service.mode == QualificationMode.NON_QUALIFIED
        assert not service.is_qualified

        keys = await service.get_keys()
        assert len(keys) == 2  # Signing and timestamping keys

    async def test_initialize_qualified_raises(self, temp_key_dir):
        """Test that qualified mode raises not implemented error."""
        config = TrustServiceConfig(
            mode=QualificationMode.QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(config)

        with pytest.raises(QualifiedModeNotImplementedError):
            await service.initialize()

    async def test_key_generation(self, trust_config):
        """Test that keys are generated on first init."""
        service = TrustService(trust_config)
        await service.initialize()

        # Check key files were created
        key_files = list(trust_config.key_storage_path.glob("*.pem"))
        assert len(key_files) == 4  # 2 keys + 2 certs

    async def test_key_persistence(self, trust_config):
        """Test that keys are loaded from storage on subsequent inits."""
        # First init - generates keys
        service1 = TrustService(trust_config)
        await service1.initialize()
        keys1 = await service1.get_keys()

        # Second init - loads existing keys
        service2 = TrustService(trust_config)
        await service2.initialize()
        keys2 = await service2.get_keys()

        # Keys should have same IDs
        assert {k.key_id for k in keys1} == {k.key_id for k in keys2}

    async def test_operations_before_init_fail(self, trust_config):
        """Test that operations fail before initialization."""
        service = TrustService(trust_config)

        with pytest.raises(TrustServiceError, match="not initialized"):
            await service.seal(b"data")


# ---------------------------------------------------------------------------
# Sealing Tests
# ---------------------------------------------------------------------------


class TestSealing:
    """Tests for data sealing operations."""

    async def test_seal_basic(self, trust_service, test_data):
        """Test basic sealing operation."""
        sealed = await trust_service.seal(test_data)

        assert sealed.seal_id.startswith("seal-")
        assert len(sealed.signature) > 0
        assert sealed.key_id.startswith("seal-")
        assert len(sealed.certificate_chain) == 1
        assert sealed.qualification_label == QualificationMode.NON_QUALIFIED
        assert sealed.policy_snapshot_id == "test-policy-v1"

    async def test_seal_content_hash(self, trust_service, test_data):
        """Test that seal contains correct content hash."""
        sealed = await trust_service.seal(test_data)

        expected_hash = hashlib.sha384(test_data).hexdigest()
        assert sealed.content_hash == expected_hash

    async def test_seal_with_metadata(self, trust_service, test_data):
        """Test sealing with optional metadata."""
        metadata = {"delivery_id": "test-123", "type": "evidence"}
        sealed = await trust_service.seal(test_data, metadata=metadata)

        assert sealed.seal_id is not None

    async def test_seal_different_data_different_signatures(self, trust_service):
        """Test that different data produces different signatures."""
        sealed1 = await trust_service.seal(b"data one")
        sealed2 = await trust_service.seal(b"data two")

        assert sealed1.signature != sealed2.signature
        assert sealed1.content_hash != sealed2.content_hash

    async def test_seal_algorithm_suite(self, trust_service, test_data):
        """Test that seal contains algorithm suite info."""
        sealed = await trust_service.seal(test_data)

        assert sealed.algorithm_suite.version == "2026.1"
        assert sealed.algorithm_suite.hash_algorithm == "sha384"
        assert sealed.algorithm_suite.signature_algorithm == "ECDSA-P384"

    async def test_seal_certificate_valid(self, trust_service, test_data):
        """Test that seal certificate is valid."""
        sealed = await trust_service.seal(test_data)

        cert_pem = sealed.certificate_chain[0].encode("utf-8")
        cert = x509.load_pem_x509_certificate(cert_pem)

        assert cert.not_valid_before_utc <= datetime.now(UTC)
        assert cert.not_valid_after_utc > datetime.now(UTC)

    async def test_seal_to_dict(self, trust_service, test_data):
        """Test SealedData serialization."""
        sealed = await trust_service.seal(test_data)
        data = sealed.to_dict()

        assert "seal_id" in data
        assert "signature" in data
        assert "algorithm_suite" in data
        assert "certificate_chain" in data
        assert data["qualification_label"] == "non_qualified"


# ---------------------------------------------------------------------------
# Timestamp Tests
# ---------------------------------------------------------------------------


class TestTimestamping:
    """Tests for timestamping operations."""

    async def test_timestamp_basic(self, trust_service, test_data):
        """Test basic timestamping operation."""
        token = await trust_service.timestamp(test_data)

        assert token.token_id.startswith("tst-")
        assert token.timestamp <= datetime.now(UTC)
        assert len(token.signature) > 0
        assert token.serial_number >= 1
        assert token.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_timestamp_message_imprint(self, trust_service, test_data):
        """Test that timestamp contains correct message imprint."""
        token = await trust_service.timestamp(test_data)

        expected_hash = hashlib.sha384(test_data).hexdigest()
        assert token.message_imprint == expected_hash
        assert token.hash_algorithm == "sha384"

    async def test_timestamp_sha256(self, trust_service, test_data):
        """Test timestamping with SHA-256."""
        token = await trust_service.timestamp(test_data, hash_algorithm="sha256")

        expected_hash = hashlib.sha256(test_data).hexdigest()
        assert token.message_imprint == expected_hash
        assert token.hash_algorithm == "sha256"

    async def test_timestamp_sha512(self, trust_service, test_data):
        """Test timestamping with SHA-512."""
        token = await trust_service.timestamp(test_data, hash_algorithm="sha512")

        expected_hash = hashlib.sha512(test_data).hexdigest()
        assert token.message_imprint == expected_hash
        assert token.hash_algorithm == "sha512"

    async def test_timestamp_unsupported_algorithm(self, trust_service, test_data):
        """Test that unsupported hash algorithm raises error."""
        with pytest.raises(TrustServiceError, match="Unsupported hash algorithm"):
            await trust_service.timestamp(test_data, hash_algorithm="md5")

    async def test_timestamp_serial_increments(self, trust_service, test_data):
        """Test that serial numbers increment."""
        token1 = await trust_service.timestamp(test_data)
        token2 = await trust_service.timestamp(test_data)
        token3 = await trust_service.timestamp(test_data)

        assert token2.serial_number == token1.serial_number + 1
        assert token3.serial_number == token2.serial_number + 1

    async def test_timestamp_policy_oid(self, trust_service, test_data):
        """Test that timestamp contains policy OID."""
        token = await trust_service.timestamp(test_data)
        assert token.policy_oid is not None

    async def test_timestamp_to_dict(self, trust_service, test_data):
        """Test TimestampToken serialization."""
        token = await trust_service.timestamp(test_data)
        data = token.to_dict()

        assert "token_id" in data
        assert "timestamp" in data
        assert "message_imprint" in data
        assert "signature" in data
        assert data["qualification_label"] == "non_qualified"


# ---------------------------------------------------------------------------
# Checkpoint Tests
# ---------------------------------------------------------------------------


class TestCheckpointing:
    """Tests for audit log checkpoint operations."""

    async def test_checkpoint_basic(self, trust_service):
        """Test basic checkpoint operation."""
        audit_hash = hashlib.sha256(b"audit log state").hexdigest()

        checkpoint = await trust_service.checkpoint(
            audit_log_hash=audit_hash,
            stream="SECURITY",
            sequence_number=100,
        )

        assert checkpoint.checkpoint_id.startswith("ckpt-")
        assert checkpoint.audit_log_hash == audit_hash
        assert checkpoint.stream == "SECURITY"
        assert checkpoint.sequence_number == 100

    async def test_checkpoint_contains_seal(self, trust_service):
        """Test that checkpoint contains a seal."""
        audit_hash = hashlib.sha256(b"audit log").hexdigest()

        checkpoint = await trust_service.checkpoint(
            audit_log_hash=audit_hash,
            stream="EVIDENCE",
            sequence_number=50,
        )

        assert checkpoint.seal is not None
        assert checkpoint.seal.seal_id.startswith("seal-")
        assert checkpoint.seal.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_checkpoint_contains_timestamp(self, trust_service):
        """Test that checkpoint contains a timestamp."""
        audit_hash = hashlib.sha256(b"audit log").hexdigest()

        checkpoint = await trust_service.checkpoint(
            audit_log_hash=audit_hash,
            stream="OPS",
            sequence_number=25,
        )

        assert checkpoint.timestamp is not None
        assert checkpoint.timestamp.token_id.startswith("tst-")
        assert checkpoint.timestamp.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_checkpoint_to_dict(self, trust_service):
        """Test SealedCheckpoint serialization."""
        audit_hash = hashlib.sha256(b"audit log").hexdigest()

        checkpoint = await trust_service.checkpoint(
            audit_log_hash=audit_hash,
            stream="SECURITY",
            sequence_number=10,
        )
        data = checkpoint.to_dict()

        assert "checkpoint_id" in data
        assert "audit_log_hash" in data
        assert "seal" in data
        assert "timestamp" in data


# ---------------------------------------------------------------------------
# Key Management Tests
# ---------------------------------------------------------------------------


class TestKeyManagement:
    """Tests for key management operations."""

    async def test_get_keys(self, trust_service):
        """Test getting all keys."""
        keys = await trust_service.get_keys()

        assert len(keys) == 2
        purposes = {k.purpose for k in keys}
        assert KeyPurpose.SIGNING in purposes
        assert KeyPurpose.TIMESTAMPING in purposes

    async def test_get_key_by_id(self, trust_service):
        """Test getting a specific key."""
        keys = await trust_service.get_keys()
        key_id = keys[0].key_id

        key = await trust_service.get_key(key_id)
        assert key.key_id == key_id

    async def test_get_key_not_found(self, trust_service):
        """Test getting non-existent key raises error."""
        with pytest.raises(KeyNotFoundError):
            await trust_service.get_key("nonexistent-key-id")

    async def test_key_info_structure(self, trust_service):
        """Test KeyInfo structure."""
        keys = await trust_service.get_keys()
        key = keys[0]

        assert key.key_id is not None
        assert key.purpose in (KeyPurpose.SIGNING, KeyPurpose.TIMESTAMPING)
        assert key.status == KeyStatus.ACTIVE
        assert key.algorithm.version is not None
        assert key.created_at is not None
        assert key.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert key.qualification_mode == QualificationMode.NON_QUALIFIED

    async def test_key_info_to_dict(self, trust_service):
        """Test KeyInfo serialization."""
        keys = await trust_service.get_keys()
        data = keys[0].to_dict()

        assert "key_id" in data
        assert "purpose" in data
        assert "algorithm" in data
        assert "status" in data
        assert "certificate_pem" in data


# ---------------------------------------------------------------------------
# Verification Tests
# ---------------------------------------------------------------------------


class TestVerification:
    """Tests for seal and timestamp verification."""

    async def test_verify_seal_success(self, trust_service, test_data):
        """Test successful seal verification."""
        sealed = await trust_service.seal(test_data)

        result = await trust_service.verify_seal(test_data, sealed)
        assert result is True

    async def test_verify_seal_wrong_data(self, trust_service, test_data):
        """Test seal verification fails with wrong data."""
        sealed = await trust_service.seal(test_data)

        result = await trust_service.verify_seal(b"wrong data", sealed)
        assert result is False

    async def test_verify_timestamp_success(self, trust_service, test_data):
        """Test successful timestamp verification."""
        token = await trust_service.timestamp(test_data)

        result = await trust_service.verify_timestamp(test_data, token)
        assert result is True

    async def test_verify_timestamp_wrong_data(self, trust_service, test_data):
        """Test timestamp verification fails with wrong data."""
        token = await trust_service.timestamp(test_data)

        result = await trust_service.verify_timestamp(b"wrong data", token)
        assert result is False


# ---------------------------------------------------------------------------
# Factory Function Tests
# ---------------------------------------------------------------------------


class TestFactoryFunction:
    """Tests for create_trust_service factory."""

    async def test_create_trust_service(self, temp_key_dir):
        """Test factory function creates initialized service."""
        service = await create_trust_service(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )

        assert service.mode == QualificationMode.NON_QUALIFIED
        keys = await service.get_keys()
        assert len(keys) == 2

    async def test_create_with_password(self, temp_key_dir):
        """Test factory function with key password."""
        service = await create_trust_service(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            key_password=b"test-password",
        )

        keys = await service.get_keys()
        assert len(keys) == 2


# ---------------------------------------------------------------------------
# API Router Tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def trust_api_client(trust_service):
    """Create async client for testing trust API."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(trust_router)

    # Inject the test service
    get_trust_service_for_testing(trust_service)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


class TestTrustAPI:
    """Tests for trust API endpoints."""

    async def test_health_endpoint(self, trust_api_client):
        """Test health check endpoint."""
        response = await trust_api_client.get("/trust/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert data["mode"] == "non_qualified"
        assert data["initialized"] is True

    async def test_seal_endpoint(self, trust_api_client, test_data_b64):
        """Test seal endpoint."""
        response = await trust_api_client.post(
            "/trust/seal",
            json={"data": test_data_b64},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["seal_id"].startswith("seal-")
        assert data["qualification_label"] == "non_qualified"

    async def test_seal_with_metadata(self, trust_api_client, test_data_b64):
        """Test seal endpoint with metadata."""
        response = await trust_api_client.post(
            "/trust/seal",
            json={
                "data": test_data_b64,
                "metadata": {"delivery_id": "test-123"},
            },
        )
        assert response.status_code == 200

    async def test_seal_invalid_base64(self, trust_api_client):
        """Test seal endpoint rejects invalid base64."""
        response = await trust_api_client.post(
            "/trust/seal",
            json={"data": "not-valid-base64!!!"},
        )
        assert response.status_code == 400

    async def test_timestamp_endpoint(self, trust_api_client, test_data_b64):
        """Test timestamp endpoint."""
        response = await trust_api_client.post(
            "/trust/timestamp",
            json={"data": test_data_b64},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["token_id"].startswith("tst-")
        assert data["qualification_label"] == "non_qualified"

    async def test_timestamp_with_algorithm(self, trust_api_client, test_data_b64):
        """Test timestamp endpoint with specific hash algorithm."""
        response = await trust_api_client.post(
            "/trust/timestamp",
            json={"data": test_data_b64, "hash_algorithm": "sha256"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["hash_algorithm"] == "sha256"

    async def test_checkpoint_endpoint(self, trust_api_client):
        """Test checkpoint endpoint."""
        audit_hash = hashlib.sha256(b"audit log").hexdigest()

        response = await trust_api_client.post(
            "/trust/checkpoint",
            json={
                "audit_log_hash": audit_hash,
                "stream": "SECURITY",
                "sequence_number": 100,
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["checkpoint_id"].startswith("ckpt-")
        assert "seal" in data
        assert "timestamp" in data

    async def test_get_keys_endpoint(self, trust_api_client):
        """Test get keys endpoint."""
        response = await trust_api_client.get("/trust/keys")
        assert response.status_code == 200

        data = response.json()
        assert "keys" in data
        assert len(data["keys"]) == 2
        assert data["mode"] == "non_qualified"

    async def test_get_key_endpoint(self, trust_api_client):
        """Test get specific key endpoint."""
        # First get all keys to find an ID
        keys_response = await trust_api_client.get("/trust/keys")
        key_id = keys_response.json()["keys"][0]["key_id"]

        response = await trust_api_client.get(f"/trust/keys/{key_id}")
        assert response.status_code == 200

        data = response.json()
        assert data["key_id"] == key_id

    async def test_get_key_not_found(self, trust_api_client):
        """Test get key endpoint returns 404 for unknown key."""
        response = await trust_api_client.get("/trust/keys/nonexistent-key")
        assert response.status_code == 404

    async def test_rotate_key_requires_performed_by(self, trust_api_client):
        """Test key rotation requires performed_by field."""
        keys_response = await trust_api_client.get("/trust/keys")
        key_id = keys_response.json()["keys"][0]["key_id"]

        # Missing performed_by should return 422
        response = await trust_api_client.post(
            f"/trust/keys/{key_id}/rotate",
            json={"reason": "Scheduled rotation for security compliance"},
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# Qualification Label Tests
# ---------------------------------------------------------------------------


class TestQualificationLabeling:
    """Tests for qualification labeling per REQ-G02."""

    async def test_seal_labeled_non_qualified(self, trust_service, test_data):
        """Test that seals are labeled as non-qualified in dev mode."""
        sealed = await trust_service.seal(test_data)
        assert sealed.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_timestamp_labeled_non_qualified(self, trust_service, test_data):
        """Test that timestamps are labeled as non-qualified in dev mode."""
        token = await trust_service.timestamp(test_data)
        assert token.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_key_labeled_non_qualified(self, trust_service):
        """Test that keys are labeled as non-qualified in dev mode."""
        keys = await trust_service.get_keys()
        for key in keys:
            assert key.qualification_mode == QualificationMode.NON_QUALIFIED

    async def test_checkpoint_labeled_non_qualified(self, trust_service):
        """Test that checkpoints are labeled as non-qualified in dev mode."""
        audit_hash = hashlib.sha256(b"audit log").hexdigest()
        checkpoint = await trust_service.checkpoint(
            audit_log_hash=audit_hash,
            stream="SECURITY",
            sequence_number=1,
        )
        assert checkpoint.seal.qualification_label == QualificationMode.NON_QUALIFIED
        assert checkpoint.timestamp.qualification_label == QualificationMode.NON_QUALIFIED


# ---------------------------------------------------------------------------
# Key Password Tests
# ---------------------------------------------------------------------------


class TestKeyEncryption:
    """Tests for key encryption at rest."""

    async def test_keys_encrypted_with_password(self, temp_key_dir):
        """Test that keys are encrypted when password is provided."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            key_password=b"test-encryption-password",
        )
        service = TrustService(config)
        await service.initialize()

        # Private key file (not certificate) should contain encrypted key
        # Key files are named like seal-non_qualified-001.pem (without -cert)
        key_files = [f for f in temp_key_dir.glob("*.pem") if "-cert" not in f.name]
        assert len(key_files) >= 1

        key_content = key_files[0].read_text()
        assert "ENCRYPTED" in key_content

    async def test_keys_not_encrypted_without_password(self, temp_key_dir):
        """Test that keys are not encrypted when no password."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            key_password=None,
        )
        service = TrustService(config)
        await service.initialize()

        # Private key file (not certificate) should not have ENCRYPTED header
        key_files = [f for f in temp_key_dir.glob("*.pem") if "-cert" not in f.name]
        assert len(key_files) >= 1

        key_content = key_files[0].read_text()
        assert "ENCRYPTED" not in key_content


# ---------------------------------------------------------------------------
# Certificate Tests
# ---------------------------------------------------------------------------


class TestCertificates:
    """Tests for certificate generation and validation."""

    async def test_signing_certificate_key_usage(self, trust_service):
        """Test that signing certificate has correct key usage."""
        keys = await trust_service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        cert = x509.load_pem_x509_certificate(signing_key.certificate_pem.encode())
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)

        assert key_usage.value.digital_signature is True
        assert key_usage.value.content_commitment is True

    async def test_tsa_certificate_extended_key_usage(self, trust_service):
        """Test that TSA certificate has timestamping EKU."""
        keys = await trust_service.get_keys()
        tsa_key = next(k for k in keys if k.purpose == KeyPurpose.TIMESTAMPING)

        cert = x509.load_pem_x509_certificate(tsa_key.certificate_pem.encode())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)

        from cryptography.x509.oid import ExtendedKeyUsageOID

        assert ExtendedKeyUsageOID.TIME_STAMPING in eku.value

    async def test_certificate_validity_period(self, trust_service):
        """Test certificate validity period is reasonable."""
        keys = await trust_service.get_keys()

        for key in keys:
            cert = x509.load_pem_x509_certificate(key.certificate_pem.encode())
            validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days

            # Should be valid for 2 years (730 days)
            assert validity_days == 730


# ---------------------------------------------------------------------------
# Key Lifecycle Tests (REQ-H07)
# ---------------------------------------------------------------------------


class TestKeyLifecycle:
    """Tests for key lifecycle management per REQ-H07."""

    async def test_generate_key_with_auto_activate(self, trust_service):
        """Test generating a key with auto-activation."""
        key_info, ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test key generation",
            auto_activate=True,
        )

        assert key_info.key_id is not None
        assert key_info.purpose == KeyPurpose.KEK
        assert key_info.status == KeyStatus.ACTIVE
        assert key_info.qualification_mode == QualificationMode.NON_QUALIFIED

        # Verify ceremony log
        assert ceremony.ceremony_id.startswith("ceremony-")
        assert ceremony.event.action.value == "generate"
        assert ceremony.event.performed_by == "test-user"
        assert ceremony.event.new_status == KeyStatus.ACTIVE

    async def test_generate_key_pending_activation(self, trust_service):
        """Test generating a key without auto-activation."""
        key_info, ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.AUDIT_LOG_CHAIN,
            performed_by="test-user",
            reason="Test pending key",
            auto_activate=False,
        )

        assert key_info.status == KeyStatus.PENDING_ACTIVATION
        assert ceremony.event.new_status == KeyStatus.PENDING_ACTIVATION

    async def test_activate_pending_key(self, trust_service):
        """Test activating a pending key."""
        # Generate key without auto-activation
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=False,
        )

        assert key_info.status == KeyStatus.PENDING_ACTIVATION

        # Activate the key
        activated_info, ceremony = await trust_service.activate_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Activating for use",
        )

        assert activated_info.status == KeyStatus.ACTIVE
        assert ceremony.event.action.value == "activate"
        assert ceremony.event.previous_status == KeyStatus.PENDING_ACTIVATION
        assert ceremony.event.new_status == KeyStatus.ACTIVE

    async def test_activate_non_pending_key_fails(self, trust_service):
        """Test that activating an already active key fails."""
        keys = await trust_service.get_keys()
        active_key = next(k for k in keys if k.status == KeyStatus.ACTIVE)

        with pytest.raises(KeyStatusError) as exc_info:
            await trust_service.activate_key(
                active_key.key_id,
                performed_by="test-user",
                reason="Test",
            )

        assert active_key.key_id in str(exc_info.value)
        assert "activate" in str(exc_info.value)

    async def test_rotate_key(self, trust_service):
        """Test key rotation."""
        keys = await trust_service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        old_key, new_key, ceremony = await trust_service.rotate_key(
            signing_key.key_id,
            performed_by="test-user",
            reason="Scheduled rotation for security compliance",
        )

        # Old key should be retired
        assert old_key.key_id == signing_key.key_id
        assert old_key.status == KeyStatus.RETIRED

        # New key should be active with same purpose
        assert new_key.key_id != signing_key.key_id
        assert new_key.status == KeyStatus.ACTIVE
        assert new_key.purpose == KeyPurpose.SIGNING

        # Ceremony should document rotation
        assert ceremony.event.action.value == "rotate"
        assert ceremony.event.key_id == signing_key.key_id
        assert "new_key_id" in ceremony.event.metadata

    async def test_rotate_inactive_key_fails(self, trust_service):
        """Test that rotating a non-active key fails."""
        # Generate pending key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=False,
        )

        with pytest.raises(KeyStatusError):
            await trust_service.rotate_key(
                key_info.key_id,
                performed_by="test-user",
                reason="Should fail",
            )

    async def test_suspend_key(self, trust_service):
        """Test suspending a key."""
        # Generate and activate a key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # Suspend the key
        suspended_info, ceremony = await trust_service.suspend_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Security incident investigation",
        )

        assert suspended_info.status == KeyStatus.SUSPENDED
        assert ceremony.event.action.value == "suspend"
        assert ceremony.event.previous_status == KeyStatus.ACTIVE

    async def test_unsuspend_key(self, trust_service):
        """Test unsuspending a suspended key."""
        # Generate and activate a key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # Suspend the key
        await trust_service.suspend_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Investigation",
        )

        # Unsuspend the key
        unsuspended_info, ceremony = await trust_service.unsuspend_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Investigation complete, all clear",
        )

        assert unsuspended_info.status == KeyStatus.ACTIVE
        assert ceremony.event.action.value == "unsuspend"

    async def test_revoke_key(self, trust_service):
        """Test revoking a key."""
        # Generate a key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # Revoke the key
        revoked_info, ceremony = await trust_service.revoke_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Key compromise suspected",
        )

        assert revoked_info.status == KeyStatus.REVOKED
        assert ceremony.event.action.value == "revoke"

    async def test_revoke_already_revoked_fails(self, trust_service):
        """Test that revoking an already revoked key fails."""
        # Generate and revoke a key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        await trust_service.revoke_key(
            key_info.key_id,
            performed_by="test-user",
            reason="First revocation",
        )

        # Try to revoke again
        with pytest.raises(KeyStatusError):
            await trust_service.revoke_key(
                key_info.key_id,
                performed_by="test-user",
                reason="Should fail",
            )

    async def test_retire_key(self, trust_service):
        """Test retiring a key."""
        # Generate a key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # Retire the key
        retired_info, ceremony = await trust_service.retire_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Scheduled decommissioning",
        )

        assert retired_info.status == KeyStatus.RETIRED
        assert ceremony.event.action.value == "retire"

    async def test_get_lifecycle_events(self, trust_service):
        """Test retrieving lifecycle events for a key."""
        # Generate a key with some lifecycle events
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # Suspend and unsuspend
        await trust_service.suspend_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Test suspension",
        )
        await trust_service.unsuspend_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Test unsuspension",
        )

        # Get lifecycle events
        events = await trust_service.get_lifecycle_events(key_id=key_info.key_id)

        assert len(events) == 3  # generate, suspend, unsuspend
        # Events should be sorted newest first
        assert events[0].event.action.value == "unsuspend"
        assert events[1].event.action.value == "suspend"
        assert events[2].event.action.value == "generate"


# ---------------------------------------------------------------------------
# Key Inventory Tests
# ---------------------------------------------------------------------------


class TestKeyInventory:
    """Tests for key inventory functionality."""

    async def test_get_key_inventory(self, trust_service):
        """Test getting key inventory snapshot."""
        inventory = await trust_service.get_key_inventory()

        assert inventory.snapshot_id.startswith("inv-")
        assert inventory.qualification_mode == QualificationMode.NON_QUALIFIED
        assert inventory.total_keys >= 2  # At least signing and timestamping
        assert inventory.active_keys >= 2

    async def test_key_inventory_counts(self, trust_service):
        """Test that inventory counts are accurate."""
        # Generate a pending key
        await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=False,
        )

        # Generate and retire a key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.AUDIT_LOG_CHAIN,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )
        await trust_service.retire_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Retirement test",
        )

        inventory = await trust_service.get_key_inventory()

        assert inventory.pending_keys >= 1
        assert inventory.retired_keys >= 1
        assert inventory.total_keys == len(inventory.keys)

    async def test_inventory_to_dict(self, trust_service):
        """Test inventory serialization."""
        inventory = await trust_service.get_key_inventory()
        data = inventory.to_dict()

        assert "snapshot_id" in data
        assert "snapshot_at" in data
        assert "keys" in data
        assert "total_keys" in data
        assert "active_keys" in data


# ---------------------------------------------------------------------------
# Dual-Control Tests
# ---------------------------------------------------------------------------


class TestDualControl:
    """Tests for dual-control enforcement."""

    async def test_dual_control_required_for_rotate(self, temp_key_dir):
        """Test that rotation requires dual-control when enabled."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            require_dual_control=True,
        )
        service = TrustService(config)
        await service.initialize()

        keys = await service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        # Without approved_by should fail
        with pytest.raises(DualControlRequiredError):
            await service.rotate_key(
                signing_key.key_id,
                performed_by="user-1",
                reason="Test rotation",
            )

    async def test_dual_control_same_user_fails(self, temp_key_dir):
        """Test that same user cannot be both performer and approver."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            require_dual_control=True,
        )
        service = TrustService(config)
        await service.initialize()

        keys = await service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        with pytest.raises(DualControlSameUserError):
            await service.rotate_key(
                signing_key.key_id,
                performed_by="user-1",
                approved_by="user-1",  # Same user!
                reason="Test rotation",
            )

    async def test_dual_control_with_different_approver(self, temp_key_dir):
        """Test that rotation succeeds with different approver."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            require_dual_control=True,
        )
        service = TrustService(config)
        await service.initialize()

        keys = await service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        # With different approved_by should succeed
        _old_key, new_key, ceremony = await service.rotate_key(
            signing_key.key_id,
            performed_by="user-1",
            approved_by="user-2",  # Different user
            reason="Test rotation",
        )

        assert new_key.status == KeyStatus.ACTIVE
        assert ceremony.event.approved_by == "user-2"
        assert "user-1" in ceremony.witnesses
        assert "user-2" in ceremony.witnesses


# ---------------------------------------------------------------------------
# Ceremony Log Tests
# ---------------------------------------------------------------------------


class TestCeremonyLogs:
    """Tests for ceremony log generation."""

    async def test_ceremony_log_structure(self, trust_service):
        """Test ceremony log has required fields."""
        _key_info, ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test key generation",
            auto_activate=True,
        )

        assert ceremony.ceremony_id is not None
        assert ceremony.event is not None
        assert ceremony.key_info is not None
        assert ceremony.algorithm_suite is not None
        assert ceremony.policy_snapshot_id is not None
        assert ceremony.witnesses is not None
        assert ceremony.sealed_at is not None
        assert ceremony.seal_signature is not None

    async def test_ceremony_log_seal_signature(self, trust_service):
        """Test that ceremony logs have seal signatures."""
        _key_info, ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # After signing key is active, seal signature should be real
        assert ceremony.seal_signature != ""
        # First ceremony during generation may have pending signature
        # because signing key wasn't active yet

    async def test_ceremony_log_to_dict(self, trust_service):
        """Test ceremony log serialization."""
        _key_info, ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        data = ceremony.to_dict()

        assert "ceremony_id" in data
        assert "event" in data
        assert "key_info" in data
        assert "algorithm_suite" in data
        assert "policy_snapshot_id" in data
        assert "witnesses" in data
        assert "sealed_at" in data
        assert "seal_signature" in data

    async def test_ceremony_witnesses(self, trust_service):
        """Test that ceremony witnesses are recorded."""
        _key_info, ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        assert "test-user" in ceremony.witnesses


# ---------------------------------------------------------------------------
# Key Lifecycle API Tests
# ---------------------------------------------------------------------------


class TestKeyLifecycleAPI:
    """Tests for key lifecycle API endpoints."""

    async def test_generate_key_endpoint(self, trust_api_client):
        """Test key generation API endpoint."""
        response = await trust_api_client.post(
            "/trust/keys/generate",
            json={
                "purpose": "kek",
                "performed_by": "test-user",
                "reason": "API test generation",
                "auto_activate": True,
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "key" in data
        assert "ceremony" in data
        assert data["key"]["purpose"] == "kek"
        assert data["key"]["status"] == "active"

    async def test_rotate_key_endpoint(self, trust_api_client):
        """Test key rotation API endpoint."""
        # First get an existing key
        keys_response = await trust_api_client.get("/trust/keys")
        key_id = keys_response.json()["keys"][0]["key_id"]

        response = await trust_api_client.post(
            f"/trust/keys/{key_id}/rotate",
            json={
                "performed_by": "test-user",
                "reason": "API test rotation for compliance",
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "old_key" in data
        assert "new_key" in data
        assert "ceremony" in data
        assert data["old_key"]["status"] == "retired"
        assert data["new_key"]["status"] == "active"

    async def test_suspend_key_endpoint(self, trust_api_client):
        """Test key suspension API endpoint."""
        # Generate a key first
        gen_response = await trust_api_client.post(
            "/trust/keys/generate",
            json={
                "purpose": "kek",
                "performed_by": "test-user",
                "reason": "Test key generation",
                "auto_activate": True,
            },
        )
        assert gen_response.status_code == 200, gen_response.json()
        key_id = gen_response.json()["key"]["key_id"]

        # Suspend it
        response = await trust_api_client.post(
            f"/trust/keys/{key_id}/suspend",
            json={
                "performed_by": "test-user",
                "reason": "Security investigation required",
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["key"]["status"] == "suspended"

    async def test_inventory_endpoint(self, trust_api_client):
        """Test key inventory API endpoint."""
        response = await trust_api_client.get("/trust/keys/inventory")
        assert response.status_code == 200

        data = response.json()
        assert "snapshot_id" in data
        assert "total_keys" in data
        assert "active_keys" in data
        assert "keys" in data

    async def test_ceremonies_endpoint(self, trust_api_client):
        """Test ceremonies API endpoint."""
        # Generate a key with ceremonies
        gen_response = await trust_api_client.post(
            "/trust/keys/generate",
            json={
                "purpose": "kek",
                "performed_by": "test-user",
                "reason": "Test key generation",
                "auto_activate": True,
            },
        )
        assert gen_response.status_code == 200, gen_response.json()
        key_id = gen_response.json()["key"]["key_id"]

        # Get ceremonies
        response = await trust_api_client.get(f"/trust/keys/{key_id}/ceremonies")
        assert response.status_code == 200

        data = response.json()
        assert len(data) >= 1
        assert data[0]["event"]["action"] == "generate"
