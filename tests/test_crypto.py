"""Comprehensive tests for cryptographic operations.

Tests cover:
- CMS signature generation and validation
- RFC 3161 timestamp token handling
- Hash computation (SHA-256, SHA-384, SHA-512)
- Verification bundle completeness
- Qualification label enforcement
- Key rotation scenarios
- Algorithm agility
- Edge cases and error handling

Covers: REQ-B02, REQ-C02, REQ-C03, REQ-D03, REQ-D04, REQ-G02, REQ-H07

This file provides additional coverage for crypto code beyond the basic tests
in test_trust.py and test_evidence_sealer.py, targeting 95%+ coverage.
"""

from __future__ import annotations

import base64
import hashlib
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography import x509

from qerds.services.evidence_sealer import (
    CanonicalizationError,
    EvidenceSealer,
    SealedEvidence,
    SealingError,
    VerificationBundle,
)
from qerds.services.trust import (
    AlgorithmSuite,
    DualControlRequest,
    DualControlStatus,
    KeyInfo,
    KeyInventory,
    KeyLifecycleAction,
    KeyLifecycleEvent,
    KeyNotFoundError,
    KeyPurpose,
    KeyStatus,
    KeyStatusError,
    QualificationMode,
    QualifiedModeNotImplementedError,
    SealedData,
    TimestampToken,
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
def trust_config(temp_key_dir: Path) -> TrustServiceConfig:
    """Create a test trust service configuration."""
    return TrustServiceConfig(
        mode=QualificationMode.NON_QUALIFIED,
        key_storage_path=temp_key_dir,
        key_password=None,
        organization_name="QERDS Test",
        country="FR",
        policy_snapshot_id="test-policy-v1",
    )


@pytest.fixture
async def trust_service(trust_config: TrustServiceConfig) -> TrustService:
    """Create and initialize a trust service for tests."""
    service = TrustService(trust_config)
    await service.initialize()
    return service


@pytest.fixture
def evidence_sealer(trust_service: TrustService) -> EvidenceSealer:
    """Create an evidence sealer with the test trust service."""
    return EvidenceSealer(trust_service)


@pytest.fixture
def sample_event_data() -> dict:
    """Sample event data for sealing tests."""
    return {
        "event_id": str(uuid4()),
        "delivery_id": str(uuid4()),
        "event_type": "EVT_DEPOSITED",
        "event_time": datetime.now(UTC).isoformat(),
        "actor_type": "sender",
        "actor_ref": "party-123",
        "inputs_hashes": {
            "content": hashlib.sha256(b"test content").hexdigest(),
            "metadata": hashlib.sha256(b"test metadata").hexdigest(),
        },
        "policy_snapshot_id": str(uuid4()),
    }


# ---------------------------------------------------------------------------
# Hash Algorithm Tests
# ---------------------------------------------------------------------------


class TestHashAlgorithms:
    """Tests for hash algorithm support and agility per REQ-D03."""

    async def test_sha256_hash_computation(self, evidence_sealer: EvidenceSealer):
        """Test SHA-256 hash computation for content binding."""
        data = b"test content for sha256"
        expected = hashlib.sha256(data).hexdigest()

        result = evidence_sealer.compute_content_hash(data)

        assert result == expected
        assert len(result) == 64  # SHA-256 produces 64 hex chars

    async def test_sha384_in_seal(self, trust_service: TrustService):
        """Test SHA-384 is used in seal operations."""
        data = b"test data for seal"
        sealed = await trust_service.seal(data)

        # Verify content hash uses SHA-384
        expected_hash = hashlib.sha384(data).hexdigest()
        assert sealed.content_hash == expected_hash

    async def test_sha384_timestamp_default(self, trust_service: TrustService):
        """Test SHA-384 is default for timestamp operations."""
        data = b"test data for timestamp"
        token = await trust_service.timestamp(data)

        assert token.hash_algorithm == "sha384"
        expected = hashlib.sha384(data).hexdigest()
        assert token.message_imprint == expected

    async def test_sha256_timestamp_explicit(self, trust_service: TrustService):
        """Test SHA-256 timestamp with explicit algorithm selection."""
        data = b"test data for sha256 timestamp"
        token = await trust_service.timestamp(data, hash_algorithm="sha256")

        assert token.hash_algorithm == "sha256"
        expected = hashlib.sha256(data).hexdigest()
        assert token.message_imprint == expected

    async def test_sha512_timestamp_explicit(self, trust_service: TrustService):
        """Test SHA-512 timestamp with explicit algorithm selection."""
        data = b"test data for sha512 timestamp"
        token = await trust_service.timestamp(data, hash_algorithm="sha512")

        assert token.hash_algorithm == "sha512"
        expected = hashlib.sha512(data).hexdigest()
        assert token.message_imprint == expected

    async def test_unsupported_algorithm_rejected(self, trust_service: TrustService):
        """Test that unsupported hash algorithms are rejected."""
        data = b"test data"

        with pytest.raises(TrustServiceError, match="Unsupported hash algorithm"):
            await trust_service.timestamp(data, hash_algorithm="md5")

    async def test_algorithm_suite_version_tracking(self, trust_service: TrustService):
        """Test algorithm suite versioning for crypto agility."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        # Verify algorithm suite has version info
        assert sealed.algorithm_suite.version == "2026.1"
        assert sealed.algorithm_suite.hash_algorithm == "sha384"
        assert sealed.algorithm_suite.signature_algorithm == "ECDSA-P384"
        assert sealed.algorithm_suite.key_size == 384


# ---------------------------------------------------------------------------
# Signature Generation and Verification Tests
# ---------------------------------------------------------------------------


class TestSignatureOperations:
    """Tests for CMS signature generation and validation."""

    async def test_seal_produces_valid_signature(self, trust_service: TrustService):
        """Test that seal operation produces verifiable signature."""
        data = b"evidence data to seal"
        sealed = await trust_service.seal(data)

        # Verify signature format
        assert sealed.signature is not None
        # Should be base64 encoded
        decoded = base64.b64decode(sealed.signature)
        assert len(decoded) > 0

    async def test_verify_seal_success(self, trust_service: TrustService):
        """Test successful seal verification."""
        data = b"test data for verification"
        sealed = await trust_service.seal(data)

        result = await trust_service.verify_seal(data, sealed)
        assert result is True

    async def test_verify_seal_wrong_data_fails(self, trust_service: TrustService):
        """Test seal verification fails with tampered data."""
        data = b"original data"
        sealed = await trust_service.seal(data)

        tampered_data = b"tampered data"
        result = await trust_service.verify_seal(tampered_data, sealed)
        assert result is False

    async def test_verify_seal_wrong_signature_fails(self, trust_service: TrustService):
        """Test seal verification fails with wrong signature."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        # Create a modified seal with wrong signature
        wrong_signature = base64.b64encode(b"wrong signature").decode()
        modified_sealed = SealedData(
            seal_id=sealed.seal_id,
            signature=wrong_signature,
            algorithm_suite=sealed.algorithm_suite,
            key_id=sealed.key_id,
            certificate_chain=sealed.certificate_chain,
            sealed_at=sealed.sealed_at,
            content_hash=sealed.content_hash,
            qualification_label=sealed.qualification_label,
            policy_snapshot_id=sealed.policy_snapshot_id,
        )

        result = await trust_service.verify_seal(data, modified_sealed)
        assert result is False

    async def test_seal_includes_certificate_chain(self, trust_service: TrustService):
        """Test that seal includes certificate chain for verification."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        assert len(sealed.certificate_chain) > 0
        assert "-----BEGIN CERTIFICATE-----" in sealed.certificate_chain[0]

    async def test_seal_certificate_is_valid_x509(self, trust_service: TrustService):
        """Test seal certificate is valid X.509."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        cert_pem = sealed.certificate_chain[0].encode("utf-8")
        cert = x509.load_pem_x509_certificate(cert_pem)

        assert cert.not_valid_before_utc <= datetime.now(UTC)
        assert cert.not_valid_after_utc > datetime.now(UTC)


# ---------------------------------------------------------------------------
# Timestamp Token Tests
# ---------------------------------------------------------------------------


class TestTimestampTokens:
    """Tests for RFC 3161 timestamp token handling."""

    async def test_timestamp_token_structure(self, trust_service: TrustService):
        """Test timestamp token has required RFC 3161 fields."""
        data = b"data to timestamp"
        token = await trust_service.timestamp(data)

        assert token.token_id.startswith("tst-")
        assert token.timestamp <= datetime.now(UTC)
        assert token.message_imprint is not None
        assert token.hash_algorithm in ("sha256", "sha384", "sha512")
        assert token.serial_number >= 1
        assert token.tsa_name is not None
        assert token.signature is not None
        assert token.policy_oid is not None
        assert token.accuracy_seconds >= 0

    async def test_timestamp_serial_numbers_increment(self, trust_service: TrustService):
        """Test timestamp serial numbers are monotonically increasing."""
        data = b"test data"

        token1 = await trust_service.timestamp(data)
        token2 = await trust_service.timestamp(data)
        token3 = await trust_service.timestamp(data)

        assert token2.serial_number == token1.serial_number + 1
        assert token3.serial_number == token2.serial_number + 1

    async def test_timestamp_accuracy(self, trust_service: TrustService):
        """Test timestamp accuracy is within expected bounds."""
        before = datetime.now(UTC)
        data = b"test data"
        token = await trust_service.timestamp(data)
        after = datetime.now(UTC)

        # Timestamp should be within the test window
        assert before <= token.timestamp <= after

        # Accuracy should be reasonable (1 second default)
        assert token.accuracy_seconds == 1

    async def test_verify_timestamp_success(self, trust_service: TrustService):
        """Test successful timestamp verification."""
        data = b"test data for timestamp verification"
        token = await trust_service.timestamp(data)

        result = await trust_service.verify_timestamp(data, token)
        assert result is True

    async def test_verify_timestamp_wrong_data_fails(self, trust_service: TrustService):
        """Test timestamp verification fails with wrong data."""
        data = b"original data"
        token = await trust_service.timestamp(data)

        result = await trust_service.verify_timestamp(b"wrong data", token)
        assert result is False

    async def test_timestamp_policy_oid_present(self, trust_service: TrustService):
        """Test timestamp includes policy OID."""
        data = b"test data"
        token = await trust_service.timestamp(data)

        # Should have a policy OID (dev OID in non-qualified mode)
        assert token.policy_oid is not None
        assert len(token.policy_oid) > 0

    async def test_timestamp_qualification_label(self, trust_service: TrustService):
        """Test timestamp has correct qualification label."""
        data = b"test data"
        token = await trust_service.timestamp(data)

        assert token.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_timestamp_to_dict_serialization(self, trust_service: TrustService):
        """Test timestamp token serializes to dict correctly."""
        data = b"test data"
        token = await trust_service.timestamp(data)
        data_dict = token.to_dict()

        assert "token_id" in data_dict
        assert "timestamp" in data_dict
        assert "message_imprint" in data_dict
        assert "signature" in data_dict
        assert data_dict["qualification_label"] == "non_qualified"


# ---------------------------------------------------------------------------
# Verification Bundle Tests
# ---------------------------------------------------------------------------


class TestVerificationBundle:
    """Tests for verification bundle completeness per REQ-H01."""

    async def test_verification_bundle_completeness(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test verification bundle has all required material."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        bundle = sealed.verification_bundle

        # Required fields per REQ-H01
        assert bundle.signing_cert_chain is not None
        assert len(bundle.signing_cert_chain) > 0
        assert bundle.policy_oid is not None
        assert bundle.hash_algorithm is not None
        assert bundle.signature_algorithm is not None
        assert bundle.algorithm_suite_version is not None
        assert bundle.created_at is not None

    async def test_verification_bundle_certs_are_pem(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test signing certs are in PEM format."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        bundle = sealed.verification_bundle

        for cert_pem in bundle.signing_cert_chain:
            assert "-----BEGIN CERTIFICATE-----" in cert_pem
            assert "-----END CERTIFICATE-----" in cert_pem
            # Should be loadable
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            assert cert is not None

    async def test_verification_bundle_algorithm_info(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test verification bundle includes algorithm information."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        bundle = sealed.verification_bundle

        # Should have algorithm info for future verification
        assert bundle.hash_algorithm == "sha384"
        assert "ECDSA" in bundle.signature_algorithm
        assert bundle.algorithm_suite_version == "2026.1"

    def test_verification_bundle_immutable(self):
        """Test VerificationBundle is immutable (frozen dataclass)."""
        bundle = VerificationBundle(
            signing_cert_chain=["cert1"],
            tsa_cert_chain=[],
            policy_oid="1.2.3.4",
            hash_algorithm="sha384",
            signature_algorithm="ECDSA-P384",
            algorithm_suite_version="2026.1",
            created_at="2024-01-01T00:00:00Z",
        )

        with pytest.raises(AttributeError):
            bundle.hash_algorithm = "sha256"


# ---------------------------------------------------------------------------
# Qualification Label Enforcement Tests (REQ-G02)
# ---------------------------------------------------------------------------


class TestQualificationLabels:
    """Tests for qualification label enforcement per REQ-G02."""

    async def test_non_qualified_seal_labeled(self, trust_service: TrustService):
        """Test seals in non-qualified mode are labeled."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        assert sealed.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_non_qualified_timestamp_labeled(self, trust_service: TrustService):
        """Test timestamps in non-qualified mode are labeled."""
        data = b"test data"
        token = await trust_service.timestamp(data)

        assert token.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_non_qualified_checkpoint_labeled(self, trust_service: TrustService):
        """Test checkpoints in non-qualified mode are labeled."""
        checkpoint = await trust_service.checkpoint(
            audit_log_hash="abc123",
            stream="SECURITY",
            sequence_number=1,
        )

        assert checkpoint.seal.qualification_label == QualificationMode.NON_QUALIFIED
        assert checkpoint.timestamp.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_sealed_evidence_labeled(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test sealed evidence has qualification label."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        assert sealed.qualification_label == "non_qualified"
        assert sealed.provider_attestation["qualification_label"] == "non_qualified"
        assert sealed.time_attestation["qualification_label"] == "non_qualified"

    async def test_key_labeled(self, trust_service: TrustService):
        """Test keys are labeled with qualification mode."""
        keys = await trust_service.get_keys()

        for key in keys:
            assert key.qualification_mode == QualificationMode.NON_QUALIFIED

    async def test_qualified_mode_not_implemented(self, temp_key_dir: Path):
        """Test qualified mode raises not implemented error."""
        config = TrustServiceConfig(
            mode=QualificationMode.QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(config)

        with pytest.raises(QualifiedModeNotImplementedError):
            await service.initialize()


# ---------------------------------------------------------------------------
# Key Rotation Tests (REQ-H07)
# ---------------------------------------------------------------------------


class TestKeyRotation:
    """Tests for key rotation scenarios per REQ-H07."""

    async def test_rotate_signing_key(self, trust_service: TrustService):
        """Test rotating the signing key."""
        keys = await trust_service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        old_key, new_key, _ceremony = await trust_service.rotate_key(
            signing_key.key_id,
            performed_by="test-user",
            reason="Scheduled rotation",
        )

        # Old key retired, new key active
        assert old_key.status == KeyStatus.RETIRED
        assert new_key.status == KeyStatus.ACTIVE
        assert new_key.key_id != old_key.key_id
        assert new_key.purpose == KeyPurpose.SIGNING

    async def test_rotate_timestamping_key(self, trust_service: TrustService):
        """Test rotating the timestamping key."""
        keys = await trust_service.get_keys()
        tsa_key = next(k for k in keys if k.purpose == KeyPurpose.TIMESTAMPING)

        old_key, new_key, _ceremony = await trust_service.rotate_key(
            tsa_key.key_id,
            performed_by="test-user",
            reason="Scheduled rotation",
        )

        assert old_key.status == KeyStatus.RETIRED
        assert new_key.status == KeyStatus.ACTIVE
        assert new_key.purpose == KeyPurpose.TIMESTAMPING

    async def test_seal_after_rotation(self, trust_service: TrustService):
        """Test sealing still works after key rotation."""
        keys = await trust_service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        # Rotate
        await trust_service.rotate_key(
            signing_key.key_id,
            performed_by="test-user",
            reason="Rotation",
        )

        # Should still be able to seal
        data = b"test data after rotation"
        sealed = await trust_service.seal(data)
        assert sealed.seal_id is not None

        # Verification should work with new key
        result = await trust_service.verify_seal(data, sealed)
        assert result is True

    async def test_timestamp_after_rotation(self, trust_service: TrustService):
        """Test timestamping still works after key rotation."""
        keys = await trust_service.get_keys()
        tsa_key = next(k for k in keys if k.purpose == KeyPurpose.TIMESTAMPING)

        # Rotate
        await trust_service.rotate_key(
            tsa_key.key_id,
            performed_by="test-user",
            reason="Rotation",
        )

        # Should still be able to timestamp
        data = b"test data after rotation"
        token = await trust_service.timestamp(data)
        assert token.token_id is not None

        # Verification should work with new key
        result = await trust_service.verify_timestamp(data, token)
        assert result is True

    async def test_rotate_non_active_key_fails(self, trust_service: TrustService):
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

    async def test_rotation_ceremony_log(self, trust_service: TrustService):
        """Test rotation generates ceremony log."""
        keys = await trust_service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)

        _old_key, new_key, ceremony = await trust_service.rotate_key(
            signing_key.key_id,
            performed_by="test-user",
            reason="Scheduled rotation for security",
        )

        assert ceremony.ceremony_id.startswith("ceremony-")
        assert ceremony.event.action == KeyLifecycleAction.ROTATE
        assert ceremony.event.key_id == signing_key.key_id
        assert "new_key_id" in ceremony.event.metadata
        assert ceremony.event.metadata["new_key_id"] == new_key.key_id


# ---------------------------------------------------------------------------
# Key Lifecycle Edge Cases
# ---------------------------------------------------------------------------


class TestKeyLifecycleEdgeCases:
    """Additional tests for key lifecycle edge cases."""

    async def test_retire_suspended_key(self, trust_service: TrustService):
        """Test retiring a suspended key is allowed."""
        # Generate and activate key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # Suspend it
        await trust_service.suspend_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Investigation",
        )

        # Retire it (should work from suspended state)
        retired_info, _ceremony = await trust_service.retire_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Decommission after investigation",
        )

        assert retired_info.status == KeyStatus.RETIRED

    async def test_retire_pending_key_fails(self, trust_service: TrustService):
        """Test retiring a pending key fails."""
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=False,
        )

        with pytest.raises(KeyStatusError):
            await trust_service.retire_key(
                key_info.key_id,
                performed_by="test-user",
                reason="Should fail",
            )

    async def test_suspend_non_active_key_fails(self, trust_service: TrustService):
        """Test suspending a non-active key fails."""
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=False,
        )

        with pytest.raises(KeyStatusError):
            await trust_service.suspend_key(
                key_info.key_id,
                performed_by="test-user",
                reason="Should fail",
            )

    async def test_unsuspend_non_suspended_key_fails(self, trust_service: TrustService):
        """Test unsuspending a non-suspended key fails."""
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        with pytest.raises(KeyStatusError):
            await trust_service.unsuspend_key(
                key_info.key_id,
                performed_by="test-user",
                reason="Should fail",
            )

    async def test_get_key_not_found(self, trust_service: TrustService):
        """Test getting non-existent key raises error."""
        with pytest.raises(KeyNotFoundError):
            await trust_service.get_key("nonexistent-key-id")

    async def test_lifecycle_events_filtering(self, trust_service: TrustService):
        """Test lifecycle events can be filtered by key."""
        # Generate two keys
        key1, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test 1",
            auto_activate=True,
        )
        _key2, _ = await trust_service.generate_key(
            purpose=KeyPurpose.AUDIT_LOG_CHAIN,
            performed_by="test-user",
            reason="Test 2",
            auto_activate=True,
        )

        # Get events for key1 only
        events = await trust_service.get_lifecycle_events(key_id=key1.key_id)

        assert len(events) == 1
        assert events[0].event.key_id == key1.key_id


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for error handling in crypto operations."""

    async def test_seal_before_initialization_fails(self, trust_config: TrustServiceConfig):
        """Test seal fails if service not initialized."""
        service = TrustService(trust_config)
        # Don't initialize

        with pytest.raises(TrustServiceError, match="not initialized"):
            await service.seal(b"data")

    async def test_timestamp_before_initialization_fails(self, trust_config: TrustServiceConfig):
        """Test timestamp fails if service not initialized."""
        service = TrustService(trust_config)

        with pytest.raises(TrustServiceError, match="not initialized"):
            await service.timestamp(b"data")

    async def test_checkpoint_before_initialization_fails(self, trust_config: TrustServiceConfig):
        """Test checkpoint fails if service not initialized."""
        service = TrustService(trust_config)

        with pytest.raises(TrustServiceError, match="not initialized"):
            await service.checkpoint(
                audit_log_hash="abc",
                stream="TEST",
                sequence_number=1,
            )

    async def test_canonicalization_error_propagates(self, evidence_sealer: EvidenceSealer):
        """Test canonicalization errors are properly raised."""
        # Create circular reference that can't be JSON serialized
        data: dict = {"key": "value"}
        data["self"] = data

        with pytest.raises(CanonicalizationError):
            evidence_sealer.canonicalize(data)

    async def test_sealing_error_on_trust_failure(
        self, trust_service: TrustService, sample_event_data: dict
    ):
        """Test sealing error when trust service fails."""
        sealer = EvidenceSealer(trust_service)

        with (
            patch.object(trust_service, "seal", side_effect=Exception("Mock failure")),
            pytest.raises(SealingError, match="Trust service operation failed"),
        ):
            await sealer.seal_evidence(sample_event_data)


# ---------------------------------------------------------------------------
# Algorithm Suite Tests
# ---------------------------------------------------------------------------


class TestAlgorithmSuite:
    """Tests for algorithm suite configuration."""

    def test_default_suite_values(self):
        """Test default algorithm suite has expected values."""
        suite = AlgorithmSuite.default()

        assert suite.version == "2026.1"
        assert suite.hash_algorithm == "sha384"
        assert suite.signature_algorithm == "ECDSA-P384"
        assert suite.key_size == 384

    def test_custom_suite(self):
        """Test creating custom algorithm suite."""
        suite = AlgorithmSuite(
            version="custom-v1",
            hash_algorithm="sha256",
            signature_algorithm="RSA-2048",
            key_size=2048,
        )

        assert suite.version == "custom-v1"
        assert suite.hash_algorithm == "sha256"
        assert suite.key_size == 2048

    def test_suite_is_frozen(self):
        """Test algorithm suite is immutable."""
        suite = AlgorithmSuite.default()

        with pytest.raises(AttributeError):
            suite.version = "modified"


# ---------------------------------------------------------------------------
# Checkpoint Tests
# ---------------------------------------------------------------------------


class TestCheckpointOperations:
    """Tests for audit log checkpoint sealing."""

    async def test_checkpoint_structure(self, trust_service: TrustService):
        """Test checkpoint has required structure."""
        checkpoint = await trust_service.checkpoint(
            audit_log_hash="abc123def456",
            stream="SECURITY",
            sequence_number=42,
        )

        assert checkpoint.checkpoint_id.startswith("ckpt-")
        assert checkpoint.audit_log_hash == "abc123def456"
        assert checkpoint.stream == "SECURITY"
        assert checkpoint.sequence_number == 42
        assert checkpoint.seal is not None
        assert checkpoint.timestamp is not None

    async def test_checkpoint_seal_and_timestamp(self, trust_service: TrustService):
        """Test checkpoint includes both seal and timestamp."""
        checkpoint = await trust_service.checkpoint(
            audit_log_hash="hash123",
            stream="OPS",
            sequence_number=100,
        )

        # Seal present
        assert checkpoint.seal.seal_id is not None
        assert checkpoint.seal.signature is not None

        # Timestamp present
        assert checkpoint.timestamp.token_id is not None
        assert checkpoint.timestamp.signature is not None

    async def test_checkpoint_to_dict(self, trust_service: TrustService):
        """Test checkpoint serialization."""
        checkpoint = await trust_service.checkpoint(
            audit_log_hash="hash123",
            stream="EVIDENCE",
            sequence_number=50,
        )
        data = checkpoint.to_dict()

        assert "checkpoint_id" in data
        assert "audit_log_hash" in data
        assert "stream" in data
        assert "sequence_number" in data
        assert "seal" in data
        assert "timestamp" in data


# ---------------------------------------------------------------------------
# Dataclass Serialization Tests
# ---------------------------------------------------------------------------


class TestDataclassSerialization:
    """Tests for dataclass serialization methods."""

    def test_key_info_to_dict(self):
        """Test KeyInfo serialization."""
        key_info = KeyInfo(
            key_id="test-key-123",
            purpose=KeyPurpose.SIGNING,
            algorithm=AlgorithmSuite.default(),
            status=KeyStatus.ACTIVE,
            created_at=datetime(2024, 1, 1, tzinfo=UTC),
            expires_at=datetime(2026, 1, 1, tzinfo=UTC),
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            qualification_mode=QualificationMode.NON_QUALIFIED,
        )

        data = key_info.to_dict()

        assert data["key_id"] == "test-key-123"
        assert data["purpose"] == "signing"
        assert data["status"] == "active"
        assert data["qualification_mode"] == "non_qualified"
        assert "algorithm" in data

    def test_sealed_data_to_dict(self):
        """Test SealedData serialization."""
        sealed = SealedData(
            seal_id="seal-123",
            signature="base64sig==",
            algorithm_suite=AlgorithmSuite.default(),
            key_id="key-123",
            certificate_chain=["cert1"],
            sealed_at=datetime(2024, 1, 1, tzinfo=UTC),
            content_hash="abc123",
            qualification_label=QualificationMode.NON_QUALIFIED,
            policy_snapshot_id="policy-v1",
        )

        data = sealed.to_dict()

        assert data["seal_id"] == "seal-123"
        assert data["signature"] == "base64sig=="
        assert data["qualification_label"] == "non_qualified"

    def test_timestamp_token_to_dict(self):
        """Test TimestampToken serialization."""
        token = TimestampToken(
            token_id="tst-123",
            timestamp=datetime(2024, 1, 1, tzinfo=UTC),
            message_imprint="hash123",
            hash_algorithm="sha384",
            serial_number=1,
            tsa_name="Test TSA",
            signature="sig==",
            policy_oid="1.2.3.4",
            qualification_label=QualificationMode.NON_QUALIFIED,
            accuracy_seconds=1,
        )

        data = token.to_dict()

        assert data["token_id"] == "tst-123"
        assert data["hash_algorithm"] == "sha384"
        assert data["serial_number"] == 1

    def test_key_lifecycle_event_to_dict(self):
        """Test KeyLifecycleEvent serialization."""
        event = KeyLifecycleEvent(
            event_id="evt-123",
            key_id="key-123",
            action=KeyLifecycleAction.GENERATE,
            previous_status=None,
            new_status=KeyStatus.ACTIVE,
            performed_by="test-user",
            approved_by=None,
            reason="Initial generation",
            timestamp=datetime(2024, 1, 1, tzinfo=UTC),
            metadata={"test": "value"},
        )

        data = event.to_dict()

        assert data["event_id"] == "evt-123"
        assert data["action"] == "generate"
        assert data["previous_status"] is None
        assert data["new_status"] == "active"

    def test_dual_control_request_to_dict(self):
        """Test DualControlRequest serialization."""
        request = DualControlRequest(
            request_id="req-123",
            operation=KeyLifecycleAction.ROTATE,
            key_id="key-123",
            requested_by="user1",
            reason="Security rotation",
            created_at=datetime(2024, 1, 1, tzinfo=UTC),
            expires_at=datetime(2024, 1, 2, tzinfo=UTC),
            status=DualControlStatus.PENDING,
        )

        data = request.to_dict()

        assert data["request_id"] == "req-123"
        assert data["operation"] == "rotate"
        assert data["status"] == "pending"

    def test_key_inventory_to_dict(self):
        """Test KeyInventory serialization."""
        key_info = KeyInfo(
            key_id="test-key",
            purpose=KeyPurpose.SIGNING,
            algorithm=AlgorithmSuite.default(),
            status=KeyStatus.ACTIVE,
            created_at=datetime(2024, 1, 1, tzinfo=UTC),
            expires_at=None,
            certificate_pem="cert",
            qualification_mode=QualificationMode.NON_QUALIFIED,
        )

        inventory = KeyInventory(
            snapshot_id="inv-123",
            snapshot_at=datetime(2024, 1, 1, tzinfo=UTC),
            qualification_mode=QualificationMode.NON_QUALIFIED,
            policy_snapshot_id="policy-v1",
            keys=[key_info],
            total_keys=1,
            active_keys=1,
            pending_keys=0,
            retired_keys=0,
        )

        data = inventory.to_dict()

        assert data["snapshot_id"] == "inv-123"
        assert data["total_keys"] == 1
        assert data["active_keys"] == 1
        assert len(data["keys"]) == 1


# ---------------------------------------------------------------------------
# Evidence Sealing Integration Tests
# ---------------------------------------------------------------------------


class TestEvidenceSealingIntegration:
    """Integration tests for evidence sealing workflow."""

    async def test_complete_sealing_workflow(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test complete evidence sealing workflow."""
        # Seal the evidence
        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        # Verify structure
        assert isinstance(sealed, SealedEvidence)
        assert sealed.evidence_id.startswith("evd-")
        assert sealed.payload == sample_event_data
        assert sealed.canonicalization_version == "1.0"
        assert len(sealed.content_hash) == 64  # SHA-256

        # Verify attestations present
        assert sealed.provider_attestation is not None
        assert sealed.time_attestation is not None
        assert sealed.verification_bundle is not None

        # Verify qualification
        assert sealed.qualification_label == "non_qualified"

    async def test_custom_evidence_id(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test sealing with custom evidence ID."""
        custom_id = "evd-custom-test-123"
        sealed = await evidence_sealer.seal_evidence(sample_event_data, evidence_id=custom_id)

        assert sealed.evidence_id == custom_id

    async def test_canonical_bytes_match(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test canonical bytes match expected output."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        # Recompute canonical bytes
        expected_canonical = evidence_sealer.canonicalize(sample_event_data)

        assert sealed.canonical_bytes == expected_canonical

    async def test_content_hash_matches(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test content hash matches hash of canonical bytes."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        expected_hash = hashlib.sha256(sealed.canonical_bytes).hexdigest()
        assert sealed.content_hash == expected_hash

    async def test_sealed_evidence_json_roundtrip(
        self, evidence_sealer: EvidenceSealer, sample_event_data: dict
    ):
        """Test sealed evidence JSON roundtrip."""
        import json

        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        # Serialize
        json_str = sealed.to_json()

        # Deserialize
        parsed = json.loads(json_str)

        # Verify key fields preserved
        assert parsed["evidence_id"] == sealed.evidence_id
        assert parsed["content_hash"] == sealed.content_hash
        assert parsed["qualification_label"] == sealed.qualification_label


# ---------------------------------------------------------------------------
# ManagedKey Tests
# ---------------------------------------------------------------------------


class TestManagedKey:
    """Tests for ManagedKey internal operations."""

    async def test_managed_key_is_usable(self, trust_service: TrustService):
        """Test ManagedKey.is_usable() method."""
        # Generate active key
        key_info, _ = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test",
            auto_activate=True,
        )

        # Access internal keys (for testing only)
        managed_key = trust_service._keys[key_info.key_id]
        assert managed_key.is_usable() is True

        # Suspend it
        await trust_service.suspend_key(
            key_info.key_id,
            performed_by="test-user",
            reason="Test suspension",
        )

        assert managed_key.is_usable() is False

    async def test_managed_key_get_public_info(self, trust_service: TrustService):
        """Test ManagedKey.get_public_info() method."""
        keys = await trust_service.get_keys()
        key_id = keys[0].key_id

        managed_key = trust_service._keys[key_id]
        public_info = managed_key.get_public_info()

        assert public_info.key_id == key_id
        assert public_info.certificate_pem is not None
        # Should not expose private key


# ---------------------------------------------------------------------------
# Verification Edge Cases
# ---------------------------------------------------------------------------


class TestVerificationEdgeCases:
    """Tests for verification edge cases."""

    async def test_verify_seal_empty_cert_chain(self, trust_service: TrustService):
        """Test verification fails with empty certificate chain."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        # Create modified seal with empty cert chain
        modified_sealed = SealedData(
            seal_id=sealed.seal_id,
            signature=sealed.signature,
            algorithm_suite=sealed.algorithm_suite,
            key_id=sealed.key_id,
            certificate_chain=[],  # Empty chain
            sealed_at=sealed.sealed_at,
            content_hash=sealed.content_hash,
            qualification_label=sealed.qualification_label,
            policy_snapshot_id=sealed.policy_snapshot_id,
        )

        result = await trust_service.verify_seal(data, modified_sealed)
        assert result is False

    async def test_verify_seal_invalid_cert(self, trust_service: TrustService):
        """Test verification fails with invalid certificate."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        # Create modified seal with invalid cert
        modified_sealed = SealedData(
            seal_id=sealed.seal_id,
            signature=sealed.signature,
            algorithm_suite=sealed.algorithm_suite,
            key_id=sealed.key_id,
            certificate_chain=["not a valid certificate"],
            sealed_at=sealed.sealed_at,
            content_hash=sealed.content_hash,
            qualification_label=sealed.qualification_label,
            policy_snapshot_id=sealed.policy_snapshot_id,
        )

        result = await trust_service.verify_seal(data, modified_sealed)
        assert result is False

    async def test_verify_timestamp_unsupported_algorithm(self, trust_service: TrustService):
        """Test timestamp verification fails with unsupported algorithm."""
        data = b"test data"
        token = await trust_service.timestamp(data)

        # Create modified token with unsupported algorithm
        modified_token = TimestampToken(
            token_id=token.token_id,
            timestamp=token.timestamp,
            message_imprint=token.message_imprint,
            hash_algorithm="md5",  # Unsupported
            serial_number=token.serial_number,
            tsa_name=token.tsa_name,
            signature=token.signature,
            policy_oid=token.policy_oid,
            qualification_label=token.qualification_label,
            accuracy_seconds=token.accuracy_seconds,
        )

        result = await trust_service.verify_timestamp(data, modified_token)
        assert result is False


# ---------------------------------------------------------------------------
# Factory Function Tests
# ---------------------------------------------------------------------------


class TestFactoryFunctions:
    """Tests for factory functions."""

    async def test_create_trust_service_basic(self, temp_key_dir: Path):
        """Test create_trust_service factory function."""
        service = await create_trust_service(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )

        assert service.mode == QualificationMode.NON_QUALIFIED
        keys = await service.get_keys()
        assert len(keys) == 2

    async def test_create_trust_service_with_password(self, temp_key_dir: Path):
        """Test create_trust_service with key password."""
        service = await create_trust_service(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            key_password=b"test-password",
        )

        keys = await service.get_keys()
        assert len(keys) == 2

        # Verify key files are encrypted
        key_files = [f for f in temp_key_dir.glob("*.pem") if "-cert" not in f.name]
        assert len(key_files) >= 1
        content = key_files[0].read_text()
        assert "ENCRYPTED" in content

    async def test_create_trust_service_custom_org(self, temp_key_dir: Path):
        """Test create_trust_service with custom organization."""
        service = await create_trust_service(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            organization_name="Custom Org",
            country="DE",
        )

        keys = await service.get_keys()
        cert = x509.load_pem_x509_certificate(keys[0].certificate_pem.encode())

        # Verify certificate has custom organization
        org_name = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        assert org_name == "Custom Org"

        country = cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value
        assert country == "DE"


# ---------------------------------------------------------------------------
# Ceremony Log Persistence Tests
# ---------------------------------------------------------------------------


class TestCeremonyLogPersistence:
    """Tests for ceremony log persistence to file storage."""

    async def test_ceremony_log_persisted_to_file(self, temp_key_dir: Path):
        """Test ceremony logs are persisted when path is configured."""
        ceremony_path = temp_key_dir / "ceremonies"
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
            ceremony_log_path=ceremony_path,
        )
        service = TrustService(config)
        await service.initialize()

        # Generate a key (which creates a ceremony log)
        _key_info, ceremony = await service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Test generation",
            auto_activate=True,
        )

        # Verify ceremony log file was created
        assert ceremony_path.exists()
        ceremony_files = list(ceremony_path.glob("*.json"))
        assert len(ceremony_files) >= 1

        # Verify file contents
        import json

        ceremony_file = ceremony_path / f"{ceremony.ceremony_id}.json"
        assert ceremony_file.exists()

        content = json.loads(ceremony_file.read_text())
        assert content["ceremony_id"] == ceremony.ceremony_id
        assert content["event"]["action"] == "generate"


# ---------------------------------------------------------------------------
# No Active Key Tests
# ---------------------------------------------------------------------------


class TestNoActiveKey:
    """Tests for scenarios where no active key is available."""

    async def test_seal_fails_without_active_signing_key(
        self,
        temp_key_dir: Path,
    ):
        """Test seal fails when no active signing key exists."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(config)
        await service.initialize()

        # Suspend the signing key
        keys = await service.get_keys()
        signing_key = next(k for k in keys if k.purpose == KeyPurpose.SIGNING)
        await service.suspend_key(
            signing_key.key_id,
            performed_by="test-user",
            reason="Test suspension",
        )

        # Seal should fail
        with pytest.raises(TrustServiceError, match="No active key found"):
            await service.seal(b"test data")

    async def test_timestamp_fails_without_active_tsa_key(
        self,
        temp_key_dir: Path,
    ):
        """Test timestamp fails when no active TSA key exists."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(config)
        await service.initialize()

        # Suspend the TSA key
        keys = await service.get_keys()
        tsa_key = next(k for k in keys if k.purpose == KeyPurpose.TIMESTAMPING)
        await service.suspend_key(
            tsa_key.key_id,
            performed_by="test-user",
            reason="Test suspension",
        )

        # Timestamp should fail
        with pytest.raises(TrustServiceError, match="No active key found"):
            await service.timestamp(b"test data")


# ---------------------------------------------------------------------------
# Timestamp Verification Edge Cases
# ---------------------------------------------------------------------------


class TestTimestampVerificationAlgorithms:
    """Tests for timestamp verification with different hash algorithms."""

    async def test_verify_timestamp_sha256(self, trust_service: TrustService):
        """Test timestamp verification with SHA-256."""
        data = b"test data for sha256 verification"
        token = await trust_service.timestamp(data, hash_algorithm="sha256")

        result = await trust_service.verify_timestamp(data, token)
        assert result is True

    async def test_verify_timestamp_sha512(self, trust_service: TrustService):
        """Test timestamp verification with SHA-512."""
        data = b"test data for sha512 verification"
        token = await trust_service.timestamp(data, hash_algorithm="sha512")

        result = await trust_service.verify_timestamp(data, token)
        assert result is True

    async def test_verify_timestamp_wrong_imprint(self, trust_service: TrustService):
        """Test timestamp verification fails with wrong message imprint."""
        data = b"original data"
        token = await trust_service.timestamp(data)

        # Create modified token with wrong imprint
        modified_token = TimestampToken(
            token_id=token.token_id,
            timestamp=token.timestamp,
            message_imprint="wrong_imprint_hash",  # Wrong hash
            hash_algorithm=token.hash_algorithm,
            serial_number=token.serial_number,
            tsa_name=token.tsa_name,
            signature=token.signature,
            policy_oid=token.policy_oid,
            qualification_label=token.qualification_label,
            accuracy_seconds=token.accuracy_seconds,
        )

        result = await trust_service.verify_timestamp(data, modified_token)
        assert result is False

    async def test_verify_timestamp_invalid_signature(self, trust_service: TrustService):
        """Test timestamp verification fails with invalid signature."""
        data = b"test data"
        token = await trust_service.timestamp(data)

        # Create modified token with invalid signature
        modified_token = TimestampToken(
            token_id=token.token_id,
            timestamp=token.timestamp,
            message_imprint=token.message_imprint,
            hash_algorithm=token.hash_algorithm,
            serial_number=token.serial_number,
            tsa_name=token.tsa_name,
            signature=base64.b64encode(b"invalid signature").decode(),  # Invalid
            policy_oid=token.policy_oid,
            qualification_label=token.qualification_label,
            accuracy_seconds=token.accuracy_seconds,
        )

        result = await trust_service.verify_timestamp(data, modified_token)
        assert result is False


# ---------------------------------------------------------------------------
# Seal Verification Edge Cases
# ---------------------------------------------------------------------------


class TestSealVerificationEdgeCases:
    """Additional edge case tests for seal verification."""

    async def test_verify_seal_content_hash_mismatch(self, trust_service: TrustService):
        """Test seal verification fails when content hash doesn't match."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        # Create modified seal with wrong content hash
        modified_sealed = SealedData(
            seal_id=sealed.seal_id,
            signature=sealed.signature,
            algorithm_suite=sealed.algorithm_suite,
            key_id=sealed.key_id,
            certificate_chain=sealed.certificate_chain,
            sealed_at=sealed.sealed_at,
            content_hash="wrong_hash_value",  # Wrong hash
            qualification_label=sealed.qualification_label,
            policy_snapshot_id=sealed.policy_snapshot_id,
        )

        result = await trust_service.verify_seal(data, modified_sealed)
        assert result is False

    async def test_verify_seal_catches_exception(self, trust_service: TrustService):
        """Test seal verification handles exceptions gracefully."""
        data = b"test data"
        sealed = await trust_service.seal(data)

        # Create seal with malformed certificate
        modified_sealed = SealedData(
            seal_id=sealed.seal_id,
            signature=sealed.signature,
            algorithm_suite=sealed.algorithm_suite,
            key_id=sealed.key_id,
            certificate_chain=["-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"],
            sealed_at=sealed.sealed_at,
            content_hash=sealed.content_hash,
            qualification_label=sealed.qualification_label,
            policy_snapshot_id=sealed.policy_snapshot_id,
        )

        # Should return False, not raise
        result = await trust_service.verify_seal(data, modified_sealed)
        assert result is False


# ---------------------------------------------------------------------------
# Key Inventory Edge Cases
# ---------------------------------------------------------------------------


class TestKeyInventoryEdgeCases:
    """Edge case tests for key inventory."""

    async def test_get_key_inventory_before_init_fails(self, trust_config: TrustServiceConfig):
        """Test get_key_inventory fails before initialization."""
        service = TrustService(trust_config)

        with pytest.raises(TrustServiceError, match="not initialized"):
            await service.get_key_inventory()

    async def test_get_keys_before_init_fails(self, trust_config: TrustServiceConfig):
        """Test get_keys fails before initialization."""
        service = TrustService(trust_config)

        with pytest.raises(TrustServiceError, match="not initialized"):
            await service.get_keys()


# ---------------------------------------------------------------------------
# Key Generation Edge Cases
# ---------------------------------------------------------------------------


class TestKeyGenerationEdgeCases:
    """Edge case tests for key generation."""

    async def test_generate_key_before_init_fails(self, trust_config: TrustServiceConfig):
        """Test generate_key fails before initialization."""
        service = TrustService(trust_config)

        with pytest.raises(TrustServiceError, match="not initialized"):
            await service.generate_key(
                purpose=KeyPurpose.KEK,
                performed_by="test-user",
                reason="Test",
            )

    async def test_generate_kek_key(self, trust_service: TrustService):
        """Test generating KEK key type."""
        key_info, _ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="test-user",
            reason="Generate KEK",
            auto_activate=True,
        )

        assert key_info.purpose == KeyPurpose.KEK
        assert key_info.status == KeyStatus.ACTIVE

        # Verify certificate has appropriate key usage
        cert = x509.load_pem_x509_certificate(key_info.certificate_pem.encode())
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.key_encipherment is True
        assert key_usage.value.key_agreement is True

    async def test_generate_audit_log_chain_key(self, trust_service: TrustService):
        """Test generating audit log chain key type."""
        key_info, _ceremony = await trust_service.generate_key(
            purpose=KeyPurpose.AUDIT_LOG_CHAIN,
            performed_by="test-user",
            reason="Generate audit log key",
            auto_activate=True,
        )

        assert key_info.purpose == KeyPurpose.AUDIT_LOG_CHAIN
        assert key_info.status == KeyStatus.ACTIVE

        # Verify certificate has appropriate key usage
        cert = x509.load_pem_x509_certificate(key_info.certificate_pem.encode())
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert key_usage.value.digital_signature is True
        assert key_usage.value.content_commitment is True


# ---------------------------------------------------------------------------
# Lifecycle Events Edge Cases
# ---------------------------------------------------------------------------


class TestLifecycleEventsEdgeCases:
    """Edge case tests for lifecycle events."""

    async def test_get_lifecycle_events_all(self, trust_service: TrustService):
        """Test getting all lifecycle events without filtering."""
        # Generate some keys with events
        await trust_service.generate_key(
            purpose=KeyPurpose.KEK,
            performed_by="user1",
            reason="Test 1",
            auto_activate=True,
        )
        await trust_service.generate_key(
            purpose=KeyPurpose.AUDIT_LOG_CHAIN,
            performed_by="user2",
            reason="Test 2",
            auto_activate=True,
        )

        # Get all events (no filter)
        events = await trust_service.get_lifecycle_events()

        assert len(events) >= 2

    async def test_get_lifecycle_events_empty(self, temp_key_dir: Path):
        """Test getting lifecycle events when none exist for a key."""
        config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(config)
        await service.initialize()

        # Get events for a nonexistent key
        events = await service.get_lifecycle_events(key_id="nonexistent-key")

        assert len(events) == 0
