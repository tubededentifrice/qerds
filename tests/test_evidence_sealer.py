"""Tests for evidence object sealing and timestamping.

Tests cover:
- Canonicalization determinism and version tracking
- Content hash computation (SHA-256)
- Seal/timestamp integration with TrustService
- Verification bundle completeness
- Qualification label handling (REQ-G02)
- Storage to object store
"""

import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from qerds.services.evidence_sealer import (
    CANONICALIZATION_VERSION,
    CanonicalizationError,
    EvidenceSealer,
    EvidenceSealerConfig,
    SealedEvidence,
    SealingError,
    StorageError,
    StoredEvidenceResult,
    VerificationBundle,
    create_evidence_sealer,
)
from qerds.services.trust import (
    QualificationMode,
    TrustService,
    TrustServiceConfig,
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
        key_password=None,
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
def evidence_sealer(trust_service):
    """Create an evidence sealer with the test trust service."""
    return EvidenceSealer(trust_service)


@pytest.fixture
def sample_event_data():
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


@pytest.fixture
def mock_object_store():
    """Create a mock ObjectStoreClient."""
    store = MagicMock()
    store.ensure_bucket = MagicMock(return_value=True)

    # Mock upload to return UploadResult-like object
    upload_result = MagicMock()
    upload_result.sha256_digest = "abc123" * 10 + "abcd"
    upload_result.size_bytes = 1024
    store.upload = MagicMock(return_value=upload_result)

    return store


# ---------------------------------------------------------------------------
# Canonicalization Tests
# ---------------------------------------------------------------------------


class TestCanonicalization:
    """Tests for event data canonicalization."""

    def test_canonicalize_produces_bytes(self, evidence_sealer, sample_event_data):
        """canonicalize() returns bytes."""
        result = evidence_sealer.canonicalize(sample_event_data)
        assert isinstance(result, bytes)

    def test_canonicalize_is_deterministic(self, evidence_sealer, sample_event_data):
        """canonicalize() produces same output for same input."""
        result1 = evidence_sealer.canonicalize(sample_event_data)
        result2 = evidence_sealer.canonicalize(sample_event_data)
        assert result1 == result2

    def test_canonicalize_key_order_independent(self, evidence_sealer):
        """canonicalize() produces same output regardless of key order."""
        data1 = {"a": 1, "b": 2, "c": 3}
        data2 = {"c": 3, "a": 1, "b": 2}
        data3 = {"b": 2, "c": 3, "a": 1}

        result1 = evidence_sealer.canonicalize(data1)
        result2 = evidence_sealer.canonicalize(data2)
        result3 = evidence_sealer.canonicalize(data3)

        assert result1 == result2 == result3

    def test_canonicalize_nested_objects_sorted(self, evidence_sealer):
        """canonicalize() sorts nested object keys."""
        data = {
            "outer": {"z": 1, "a": 2},
            "list": [{"y": 1, "x": 2}],
        }

        result = evidence_sealer.canonicalize(data)
        decoded = result.decode("utf-8")

        # Keys should be sorted alphabetically
        assert '"outer":{"a":2,"z":1}' in decoded

    def test_canonicalize_produces_valid_utf8(self, evidence_sealer):
        """canonicalize() produces valid UTF-8 bytes."""
        data = {"unicode": "Hello \u4e16\u754c"}

        result = evidence_sealer.canonicalize(data)
        decoded = result.decode("utf-8")

        assert "Hello" in decoded

    def test_canonicalize_datetime_serialization(self, evidence_sealer):
        """canonicalize() serializes datetime objects to ISO format."""
        now = datetime(2024, 6, 15, 12, 30, 45, tzinfo=UTC)
        data = {"timestamp": now}

        result = evidence_sealer.canonicalize(data)
        decoded = result.decode("utf-8")

        assert "2024-06-15T12:30:45" in decoded

    def test_canonicalize_uuid_serialization(self, evidence_sealer):
        """canonicalize() serializes UUID objects to strings."""
        test_uuid = uuid4()
        data = {"id": test_uuid}

        result = evidence_sealer.canonicalize(data)
        decoded = result.decode("utf-8")

        assert str(test_uuid) in decoded

    def test_canonicalize_invalid_data_raises(self, evidence_sealer):
        """canonicalize() raises CanonicalizationError for circular references."""
        # Circular references cannot be JSON serialized
        data: dict = {"key": "value"}
        data["self"] = data  # Create circular reference

        with pytest.raises(CanonicalizationError):
            evidence_sealer.canonicalize(data)

    def test_canonicalize_no_whitespace(self, evidence_sealer):
        """canonicalize() uses compact separators (no whitespace)."""
        data = {"key1": "value1", "key2": "value2"}

        result = evidence_sealer.canonicalize(data)
        decoded = result.decode("utf-8")

        # Should not have spaces after : or ,
        assert ": " not in decoded
        assert ", " not in decoded


# ---------------------------------------------------------------------------
# Content Hash Tests
# ---------------------------------------------------------------------------


class TestContentHash:
    """Tests for content hash computation."""

    def test_compute_content_hash_returns_hex(self, evidence_sealer):
        """compute_content_hash() returns hex string."""
        canonical = b"test data"
        result = evidence_sealer.compute_content_hash(canonical)

        assert len(result) == 64  # SHA-256 hex is 64 chars
        assert all(c in "0123456789abcdef" for c in result)

    def test_compute_content_hash_is_sha256(self, evidence_sealer):
        """compute_content_hash() uses SHA-256."""
        canonical = b"test data"
        result = evidence_sealer.compute_content_hash(canonical)

        expected = hashlib.sha256(canonical).hexdigest()
        assert result == expected

    def test_compute_content_hash_is_deterministic(self, evidence_sealer):
        """compute_content_hash() produces same output for same input."""
        canonical = b"consistent data"

        result1 = evidence_sealer.compute_content_hash(canonical)
        result2 = evidence_sealer.compute_content_hash(canonical)

        assert result1 == result2

    def test_compute_content_hash_different_for_different_input(self, evidence_sealer):
        """compute_content_hash() produces different output for different input."""
        result1 = evidence_sealer.compute_content_hash(b"data A")
        result2 = evidence_sealer.compute_content_hash(b"data B")

        assert result1 != result2


# ---------------------------------------------------------------------------
# Seal Evidence Tests
# ---------------------------------------------------------------------------


class TestSealEvidence:
    """Tests for the seal_evidence() method."""

    @pytest.mark.asyncio
    async def test_seal_evidence_returns_sealed_evidence(self, evidence_sealer, sample_event_data):
        """seal_evidence() returns SealedEvidence object."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert isinstance(result, SealedEvidence)

    @pytest.mark.asyncio
    async def test_seal_evidence_has_evidence_id(self, evidence_sealer, sample_event_data):
        """seal_evidence() generates evidence ID."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.evidence_id.startswith("evd-")

    @pytest.mark.asyncio
    async def test_seal_evidence_custom_evidence_id(self, evidence_sealer, sample_event_data):
        """seal_evidence() accepts custom evidence ID."""
        custom_id = "evd-custom-123"
        result = await evidence_sealer.seal_evidence(sample_event_data, evidence_id=custom_id)

        assert result.evidence_id == custom_id

    @pytest.mark.asyncio
    async def test_seal_evidence_preserves_payload(self, evidence_sealer, sample_event_data):
        """seal_evidence() preserves original payload."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.payload == sample_event_data

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_canonical_bytes(self, evidence_sealer, sample_event_data):
        """seal_evidence() includes canonical bytes."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        expected_canonical = evidence_sealer.canonicalize(sample_event_data)
        assert result.canonical_bytes == expected_canonical

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_canonicalization_version(
        self, evidence_sealer, sample_event_data
    ):
        """seal_evidence() includes canonicalization version."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.canonicalization_version == CANONICALIZATION_VERSION

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_content_hash(self, evidence_sealer, sample_event_data):
        """seal_evidence() includes correct content hash."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        canonical = evidence_sealer.canonicalize(sample_event_data)
        expected_hash = hashlib.sha256(canonical).hexdigest()

        assert result.content_hash == expected_hash

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_provider_attestation(
        self, evidence_sealer, sample_event_data
    ):
        """seal_evidence() includes provider attestation (seal)."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert "seal_id" in result.provider_attestation
        assert "signature" in result.provider_attestation
        assert "certificate_chain" in result.provider_attestation

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_time_attestation(
        self, evidence_sealer, sample_event_data
    ):
        """seal_evidence() includes time attestation (timestamp)."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert "token_id" in result.time_attestation
        assert "timestamp" in result.time_attestation
        assert "message_imprint" in result.time_attestation
        assert "signature" in result.time_attestation

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_verification_bundle(
        self, evidence_sealer, sample_event_data
    ):
        """seal_evidence() includes verification bundle."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert isinstance(result.verification_bundle, VerificationBundle)
        assert len(result.verification_bundle.signing_cert_chain) > 0
        assert result.verification_bundle.hash_algorithm is not None
        assert result.verification_bundle.signature_algorithm is not None

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_qualification_label(
        self, evidence_sealer, sample_event_data
    ):
        """seal_evidence() includes qualification label (REQ-G02)."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.qualification_label == "non_qualified"

    @pytest.mark.asyncio
    async def test_seal_evidence_includes_sealed_at_timestamp(
        self, evidence_sealer, sample_event_data
    ):
        """seal_evidence() includes sealed_at timestamp."""
        before = datetime.now(UTC)
        result = await evidence_sealer.seal_evidence(sample_event_data)
        after = datetime.now(UTC)

        assert before <= result.sealed_at <= after

    @pytest.mark.asyncio
    async def test_seal_evidence_trust_service_error_raises(self, trust_service, sample_event_data):
        """seal_evidence() raises SealingError on trust service failure."""
        sealer = EvidenceSealer(trust_service)

        # Mock seal to raise exception
        with (
            patch.object(trust_service, "seal", side_effect=Exception("Seal failed")),
            pytest.raises(SealingError, match="Trust service operation failed"),
        ):
            await sealer.seal_evidence(sample_event_data)


# ---------------------------------------------------------------------------
# Verification Bundle Tests
# ---------------------------------------------------------------------------


class TestVerificationBundle:
    """Tests for verification bundle structure."""

    @pytest.mark.asyncio
    async def test_verification_bundle_has_signing_certs(self, evidence_sealer, sample_event_data):
        """Verification bundle includes signing certificate chain."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert len(result.verification_bundle.signing_cert_chain) > 0
        assert "-----BEGIN CERTIFICATE-----" in result.verification_bundle.signing_cert_chain[0]

    @pytest.mark.asyncio
    async def test_verification_bundle_has_policy_oid(self, evidence_sealer, sample_event_data):
        """Verification bundle includes policy OID."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.verification_bundle.policy_oid is not None

    @pytest.mark.asyncio
    async def test_verification_bundle_has_algorithms(self, evidence_sealer, sample_event_data):
        """Verification bundle includes algorithm information."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.verification_bundle.hash_algorithm is not None
        assert result.verification_bundle.signature_algorithm is not None
        assert result.verification_bundle.algorithm_suite_version is not None

    @pytest.mark.asyncio
    async def test_verification_bundle_has_created_at(self, evidence_sealer, sample_event_data):
        """Verification bundle includes creation timestamp."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.verification_bundle.created_at is not None

    def test_verification_bundle_to_dict(self):
        """VerificationBundle.to_dict() serializes all fields."""
        bundle = VerificationBundle(
            signing_cert_chain=["cert1", "cert2"],
            tsa_cert_chain=["tsa_cert"],
            policy_oid="1.2.3.4.5",
            hash_algorithm="sha384",
            signature_algorithm="ECDSA-P384",
            algorithm_suite_version="2026.1",
            created_at="2024-06-15T12:00:00+00:00",
        )

        data = bundle.to_dict()

        assert data["signing_cert_chain"] == ["cert1", "cert2"]
        assert data["tsa_cert_chain"] == ["tsa_cert"]
        assert data["policy_oid"] == "1.2.3.4.5"
        assert data["hash_algorithm"] == "sha384"


# ---------------------------------------------------------------------------
# Qualification Label Tests (REQ-G02)
# ---------------------------------------------------------------------------


class TestQualificationLabeling:
    """Tests for qualification labeling per REQ-G02."""

    @pytest.mark.asyncio
    async def test_non_qualified_mode_label(self, evidence_sealer, sample_event_data):
        """Evidence sealed in non-qualified mode is labeled as such."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.qualification_label == "non_qualified"

    @pytest.mark.asyncio
    async def test_qualification_label_in_provider_attestation(
        self, evidence_sealer, sample_event_data
    ):
        """Provider attestation also includes qualification label."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.provider_attestation["qualification_label"] == "non_qualified"

    @pytest.mark.asyncio
    async def test_qualification_label_in_time_attestation(
        self, evidence_sealer, sample_event_data
    ):
        """Time attestation also includes qualification label."""
        result = await evidence_sealer.seal_evidence(sample_event_data)

        assert result.time_attestation["qualification_label"] == "non_qualified"

    def test_qualification_mode_property(self, evidence_sealer):
        """qualification_mode property returns current mode."""
        assert evidence_sealer.qualification_mode == "non_qualified"


# ---------------------------------------------------------------------------
# Serialization Tests
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for SealedEvidence serialization."""

    @pytest.mark.asyncio
    async def test_to_dict_all_fields(self, evidence_sealer, sample_event_data):
        """to_dict() includes all required fields."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        data = sealed.to_dict()

        assert "evidence_id" in data
        assert "payload" in data
        assert "canonicalization_version" in data
        assert "content_hash" in data
        assert "provider_attestation" in data
        assert "time_attestation" in data
        assert "verification_bundle" in data
        assert "qualification_label" in data
        assert "sealed_at" in data

    @pytest.mark.asyncio
    async def test_to_dict_excludes_canonical_bytes(self, evidence_sealer, sample_event_data):
        """to_dict() excludes canonical_bytes (can be recomputed)."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        data = sealed.to_dict()

        assert "canonical_bytes" not in data

    @pytest.mark.asyncio
    async def test_to_json_produces_valid_json(self, evidence_sealer, sample_event_data):
        """to_json() produces valid JSON string."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        json_str = sealed.to_json()

        # Should be parseable JSON
        parsed = json.loads(json_str)
        assert parsed["evidence_id"] == sealed.evidence_id

    @pytest.mark.asyncio
    async def test_to_json_is_canonical(self, evidence_sealer, sample_event_data):
        """to_json() produces canonical JSON (sorted, compact)."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        json_str = sealed.to_json()

        # Should not have pretty-print whitespace
        assert "\n" not in json_str
        assert ": " not in json_str


# ---------------------------------------------------------------------------
# Storage Tests
# ---------------------------------------------------------------------------


class TestStoreEvidence:
    """Tests for storing sealed evidence to object store."""

    @pytest.mark.asyncio
    async def test_store_returns_result(
        self, evidence_sealer, sample_event_data, mock_object_store
    ):
        """store_sealed_evidence() returns StoredEvidenceResult."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        result = await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)

        assert isinstance(result, StoredEvidenceResult)

    @pytest.mark.asyncio
    async def test_store_creates_bucket(
        self, evidence_sealer, sample_event_data, mock_object_store
    ):
        """store_sealed_evidence() ensures bucket exists."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)

        mock_object_store.ensure_bucket.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_uploads_json(self, evidence_sealer, sample_event_data, mock_object_store):
        """store_sealed_evidence() uploads JSON data."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)

        # Verify upload was called with JSON content type
        mock_object_store.upload.assert_called_once()
        call_args = mock_object_store.upload.call_args
        assert call_args.kwargs["content_type"] == "application/json"

    @pytest.mark.asyncio
    async def test_store_key_format(self, evidence_sealer, sample_event_data, mock_object_store):
        """store_sealed_evidence() uses correct key format."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        result = await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)

        expected_key = f"sealed/{sealed.evidence_id}.json"
        assert result.storage_key == expected_key

    @pytest.mark.asyncio
    async def test_store_custom_prefix(self, evidence_sealer, sample_event_data, mock_object_store):
        """store_sealed_evidence() accepts custom key prefix."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        result = await evidence_sealer.store_sealed_evidence(
            sealed, mock_object_store, key_prefix="custom/"
        )

        assert result.storage_key.startswith("custom/")

    @pytest.mark.asyncio
    async def test_store_includes_metadata(
        self, evidence_sealer, sample_event_data, mock_object_store
    ):
        """store_sealed_evidence() includes metadata in upload."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)

        call_args = mock_object_store.upload.call_args
        metadata = call_args.kwargs["metadata"]

        assert metadata["evidence-id"] == sealed.evidence_id
        assert metadata["qualification-label"] == sealed.qualification_label
        assert metadata["content-hash"] == sealed.content_hash

    @pytest.mark.asyncio
    async def test_store_result_has_size(
        self, evidence_sealer, sample_event_data, mock_object_store
    ):
        """StoredEvidenceResult includes size_bytes."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)
        result = await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)

        assert result.size_bytes > 0

    @pytest.mark.asyncio
    async def test_store_error_raises(self, evidence_sealer, sample_event_data, mock_object_store):
        """store_sealed_evidence() raises StorageError on failure."""
        mock_object_store.upload.side_effect = Exception("Upload failed")

        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        with pytest.raises(StorageError, match="Failed to store sealed evidence"):
            await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)


# ---------------------------------------------------------------------------
# Factory Function Tests
# ---------------------------------------------------------------------------


class TestFactoryFunction:
    """Tests for create_evidence_sealer factory."""

    @pytest.mark.asyncio
    async def test_create_evidence_sealer_returns_sealer(self, trust_service):
        """create_evidence_sealer() returns EvidenceSealer."""
        sealer = await create_evidence_sealer(trust_service)

        assert isinstance(sealer, EvidenceSealer)

    @pytest.mark.asyncio
    async def test_create_with_custom_config(self, trust_service):
        """create_evidence_sealer() accepts custom configuration."""
        sealer = await create_evidence_sealer(
            trust_service,
            evidence_bucket="custom-bucket",
            storage_prefix="custom/prefix/",
        )

        assert sealer._config.evidence_bucket == "custom-bucket"
        assert sealer._config.storage_prefix == "custom/prefix/"


# ---------------------------------------------------------------------------
# Configuration Tests
# ---------------------------------------------------------------------------


class TestConfiguration:
    """Tests for EvidenceSealerConfig."""

    def test_default_config(self):
        """Default config has expected values."""
        config = EvidenceSealerConfig()

        assert config.evidence_bucket == "qerds-evidence"
        assert config.storage_prefix == "sealed/"

    def test_custom_config(self):
        """Custom config overrides defaults."""
        config = EvidenceSealerConfig(
            evidence_bucket="my-bucket",
            storage_prefix="my-prefix/",
        )

        assert config.evidence_bucket == "my-bucket"
        assert config.storage_prefix == "my-prefix/"


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestIntegration:
    """Integration tests combining multiple components."""

    @pytest.mark.asyncio
    async def test_full_sealing_workflow(
        self, evidence_sealer, sample_event_data, mock_object_store
    ):
        """Test complete sealing and storage workflow."""
        # Seal the evidence
        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        # Verify seal content
        assert sealed.evidence_id is not None
        assert sealed.payload == sample_event_data
        assert sealed.qualification_label == "non_qualified"

        # Store the evidence
        result = await evidence_sealer.store_sealed_evidence(sealed, mock_object_store)

        # Verify storage result
        assert result.evidence_id == sealed.evidence_id
        assert result.size_bytes > 0

    @pytest.mark.asyncio
    async def test_different_events_different_hashes(self, evidence_sealer):
        """Different event data produces different content hashes."""
        event1 = {"event_id": "evt-1", "data": "first"}
        event2 = {"event_id": "evt-2", "data": "second"}

        sealed1 = await evidence_sealer.seal_evidence(event1)
        sealed2 = await evidence_sealer.seal_evidence(event2)

        assert sealed1.content_hash != sealed2.content_hash
        assert sealed1.evidence_id != sealed2.evidence_id

    @pytest.mark.asyncio
    async def test_same_event_same_canonical_bytes(self, evidence_sealer):
        """Same event data produces same canonical bytes."""
        event_data = {"key": "value", "number": 42}

        sealed1 = await evidence_sealer.seal_evidence(event_data)
        sealed2 = await evidence_sealer.seal_evidence(event_data)

        # Canonical bytes should be identical
        assert sealed1.canonical_bytes == sealed2.canonical_bytes

        # Content hash should be identical
        assert sealed1.content_hash == sealed2.content_hash

        # But evidence IDs should be different (each is unique)
        assert sealed1.evidence_id != sealed2.evidence_id

    @pytest.mark.asyncio
    async def test_sealed_evidence_json_roundtrip(self, evidence_sealer, sample_event_data):
        """Sealed evidence can be serialized and parsed back."""
        sealed = await evidence_sealer.seal_evidence(sample_event_data)

        # Serialize to JSON
        json_str = sealed.to_json()

        # Parse back
        parsed = json.loads(json_str)

        # Verify key fields
        assert parsed["evidence_id"] == sealed.evidence_id
        assert parsed["payload"] == sealed.payload
        assert parsed["content_hash"] == sealed.content_hash
        assert parsed["qualification_label"] == sealed.qualification_label
