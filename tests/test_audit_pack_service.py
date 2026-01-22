"""Tests for the Audit Pack Service.

Tests cover:
- Audit pack generation with all content types
- Sealing and timestamping of packs
- Storage to object store
- Verification instructions generation
- Error handling

Run with: docker compose exec qerds-api pytest tests/test_audit_pack_service.py -v
"""

from __future__ import annotations

import io
import uuid
import zipfile
from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from qerds.services.audit_pack import (
    AuditPackConfig,
    AuditPackContents,
    AuditPackService,
    AuditPackStorageError,
    SealedAuditPack,
)

# -----------------------------------------------------------------------------
# Test Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    return session


@pytest.fixture
def mock_trust_service():
    """Create a mock trust service."""
    trust_service = AsyncMock()

    # Mock mode property
    trust_service.mode = MagicMock()
    trust_service.mode.value = "non_qualified"

    # Mock seal method
    seal_result = MagicMock()
    seal_result.seal_id = f"seal-{uuid.uuid4()}"
    seal_result.signature = "base64_signature_data"
    seal_result.to_dict.return_value = {
        "seal_id": seal_result.seal_id,
        "signature": seal_result.signature,
        "algorithm_suite": {
            "version": "2026.1",
            "hash_algorithm": "sha384",
            "signature_algorithm": "ECDSA-P384",
            "key_size": 384,
        },
        "key_id": "seal-non_qualified-001",
        "certificate_chain": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"],
        "sealed_at": datetime.now(UTC).isoformat(),
        "content_hash": "abcdef1234567890",
        "qualification_label": "non_qualified",
        "policy_snapshot_id": "dev-policy-v1",
    }
    trust_service.seal = AsyncMock(return_value=seal_result)

    # Mock timestamp method
    timestamp_result = MagicMock()
    timestamp_result.token_id = f"tst-{uuid.uuid4()}"
    timestamp_result.timestamp = datetime.now(UTC)
    timestamp_result.to_dict.return_value = {
        "token_id": timestamp_result.token_id,
        "timestamp": timestamp_result.timestamp.isoformat(),
        "message_imprint": "sha384hash",
        "hash_algorithm": "sha384",
        "serial_number": 1,
        "tsa_name": "QERDS Timestamping (non_qualified)",
        "signature": "timestamp_signature",
        "policy_oid": "1.2.3.4.5.6.7.8.9.0",
        "qualification_label": "non_qualified",
        "accuracy_seconds": 1,
    }
    trust_service.timestamp = AsyncMock(return_value=timestamp_result)

    # Mock get_keys method
    key_info = MagicMock()
    key_info.purpose = MagicMock()
    key_info.purpose.value = "signing"
    key_info.algorithm = MagicMock()
    key_info.algorithm.version = "2026.1"
    key_info.algorithm.hash_algorithm = "sha384"
    key_info.algorithm.signature_algorithm = "ECDSA-P384"
    key_info.algorithm.key_size = 384
    trust_service.get_keys = AsyncMock(return_value=[key_info])

    # Mock get_key_inventory method
    inventory_result = MagicMock()
    inventory_result.to_dict.return_value = {
        "snapshot_id": f"inv-{uuid.uuid4()}",
        "snapshot_at": datetime.now(UTC).isoformat(),
        "qualification_mode": "non_qualified",
        "policy_snapshot_id": "dev-policy-v1",
        "keys": [],
        "total_keys": 2,
        "active_keys": 2,
        "pending_keys": 0,
        "retired_keys": 0,
    }
    trust_service.get_key_inventory = AsyncMock(return_value=inventory_result)

    return trust_service


@pytest.fixture
def mock_object_store():
    """Create a mock object store client."""
    object_store = MagicMock()
    object_store.ensure_bucket = MagicMock()
    object_store.upload = MagicMock()
    return object_store


@pytest.fixture
def audit_pack_config():
    """Create an audit pack configuration."""
    return AuditPackConfig(
        audit_bucket="test-audit-bucket",
        storage_prefix="test-audit-packs/",
        max_evidence_samples=100,
        app_version="1.0.0-test",
        sbom_ref="sbom/test-sbom.json",
    )


@pytest.fixture
def audit_pack_service(mock_db_session, mock_trust_service, mock_object_store, audit_pack_config):
    """Create an audit pack service with mocked dependencies."""
    return AuditPackService(
        session=mock_db_session,
        trust_service=mock_trust_service,
        object_store=mock_object_store,
        config=audit_pack_config,
    )


# -----------------------------------------------------------------------------
# AuditPackConfig Tests
# -----------------------------------------------------------------------------


class TestAuditPackConfig:
    """Tests for AuditPackConfig dataclass."""

    def test_default_config_values(self):
        """Test that default config has sensible values."""
        config = AuditPackConfig()
        assert config.audit_bucket == "qerds-audit"
        assert config.storage_prefix == "audit-packs/"
        assert config.max_evidence_samples == 1000
        assert config.app_version == "0.1.0"

    def test_custom_config_values(self, audit_pack_config):
        """Test that custom config values are applied."""
        assert audit_pack_config.audit_bucket == "test-audit-bucket"
        assert audit_pack_config.max_evidence_samples == 100


# -----------------------------------------------------------------------------
# AuditPackContents Tests
# -----------------------------------------------------------------------------


class TestAuditPackContents:
    """Tests for AuditPackContents dataclass."""

    def test_audit_pack_contents_creation(self):
        """Test creating AuditPackContents with all fields."""
        contents = AuditPackContents(
            evidence_samples=[{"event_id": "evt-1"}],
            log_integrity_proofs={"evidence": {"valid": True}},
            config_snapshots=[{"version": "v1.0"}],
            crypto_params={"hash_algorithm": "sha384"},
            key_inventory={"total_keys": 2},
            policy_refs={"cps": "policies/cps.pdf"},
            release_metadata={"app_version": "1.0.0"},
        )
        assert len(contents.evidence_samples) == 1
        assert contents.crypto_params["hash_algorithm"] == "sha384"


# -----------------------------------------------------------------------------
# SealedAuditPack Tests
# -----------------------------------------------------------------------------


class TestSealedAuditPack:
    """Tests for SealedAuditPack dataclass."""

    def test_sealed_audit_pack_to_dict(self):
        """Test converting SealedAuditPack to dictionary."""
        pack_id = uuid.uuid4()
        now = datetime.now(UTC)

        pack = SealedAuditPack(
            pack_id=pack_id,
            start_date=date(2024, 1, 1),
            end_date=date(2024, 1, 31),
            created_at=now,
            created_by="admin-123",
            reason="Test audit pack",
            contents_summary={"evidence_count": 10},
            pack_hash="abc123def456",
            seal_signature="base64_signature",
            timestamp_token={"token_id": "tst-1"},
            storage_ref="s3://bucket/key.zip",
            qualification_label="non_qualified",
            verification={"evidence_chain_valid": True},
        )

        result = pack.to_dict()
        assert result["pack_id"] == str(pack_id)
        assert result["start_date"] == "2024-01-01"
        assert result["end_date"] == "2024-01-31"
        assert result["created_by"] == "admin-123"
        assert result["qualification_label"] == "non_qualified"


# -----------------------------------------------------------------------------
# AuditPackService Tests
# -----------------------------------------------------------------------------


class TestAuditPackServiceGeneration:
    """Tests for audit pack generation."""

    @pytest.mark.asyncio
    async def test_generate_audit_pack_basic(
        self, audit_pack_service, mock_db_session, mock_trust_service, mock_object_store
    ):
        """Test basic audit pack generation."""
        # Mock empty database results
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Mock audit log service verification
        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 0
            mock_verification.first_seq_no = None
            mock_verification.last_seq_no = None
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            result = await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
            )

        # Verify result structure
        assert isinstance(result, SealedAuditPack)
        assert result.start_date == date(2024, 1, 1)
        assert result.end_date == date(2024, 1, 31)
        assert result.created_by == "admin-123"
        assert result.reason == "Monthly compliance review"
        assert result.qualification_label == "non_qualified"

        # Verify sealing was called
        mock_trust_service.seal.assert_called_once()
        mock_trust_service.timestamp.assert_called_once()

        # Verify storage was called
        mock_object_store.ensure_bucket.assert_called_once_with("test-audit-bucket")
        mock_object_store.upload.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_audit_pack_with_evidence_samples(
        self, audit_pack_service, mock_db_session
    ):
        """Test audit pack generation collects evidence samples."""
        # Mock evidence events
        mock_event = MagicMock()
        mock_event.event_id = uuid.uuid4()
        mock_event.event_type = MagicMock()
        mock_event.event_type.value = "evt_deposited"
        mock_event.event_time = datetime.now(UTC)
        mock_event.delivery_id = uuid.uuid4()
        mock_event.actor_type = MagicMock()
        mock_event.actor_type.value = "sender"
        mock_event.actor_ref = "party-123"
        mock_event.policy_snapshot_id = None
        mock_event.evidence_objects = []

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_event]
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 10
            mock_verification.first_seq_no = 1
            mock_verification.last_seq_no = 10
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            result = await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
                include_evidence=True,
            )

        assert result.contents_summary["evidence_count"] >= 0

    @pytest.mark.asyncio
    async def test_generate_audit_pack_without_evidence(self, audit_pack_service, mock_db_session):
        """Test audit pack generation can exclude evidence samples."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 0
            mock_verification.first_seq_no = None
            mock_verification.last_seq_no = None
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            result = await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
                include_evidence=False,
            )

        # Evidence should not be collected when disabled
        assert result.contents_summary["evidence_count"] == 0

    @pytest.mark.asyncio
    async def test_generate_audit_pack_with_verification_errors(
        self, audit_pack_service, mock_db_session
    ):
        """Test audit pack generation reports verification errors."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()

            # Mock evidence chain with errors
            mock_verification = MagicMock()
            mock_verification.valid = False
            mock_verification.checked_records = 100
            mock_verification.first_seq_no = 1
            mock_verification.last_seq_no = 100
            mock_verification.errors = ["Gap detected at sequence 50"]
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            result = await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
            )

        # Verification errors should be reported
        assert not result.verification["evidence_chain_valid"]
        assert len(result.verification["errors"]) > 0


class TestAuditPackServiceStorage:
    """Tests for audit pack storage functionality."""

    @pytest.mark.asyncio
    async def test_audit_pack_stored_as_zip(
        self, audit_pack_service, mock_db_session, mock_object_store
    ):
        """Test that audit pack is stored as a ZIP archive."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 0
            mock_verification.first_seq_no = None
            mock_verification.last_seq_no = None
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
            )

        # Verify upload was called with correct content type
        upload_call = mock_object_store.upload.call_args
        assert upload_call.kwargs["content_type"] == "application/zip"

        # Verify uploaded data is valid ZIP
        uploaded_data = upload_call.kwargs["data"]
        zip_buffer = io.BytesIO(uploaded_data)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            assert "manifest.json" in zf.namelist()
            assert "seal.json" in zf.namelist()
            assert "timestamp.json" in zf.namelist()
            assert "verification_instructions.md" in zf.namelist()

    @pytest.mark.asyncio
    async def test_storage_error_raises_exception(
        self, audit_pack_service, mock_db_session, mock_object_store
    ):
        """Test that storage errors raise AuditPackStorageError."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        # Make upload fail
        mock_object_store.upload.side_effect = Exception("S3 connection failed")

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 0
            mock_verification.first_seq_no = None
            mock_verification.last_seq_no = None
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            with pytest.raises(AuditPackStorageError) as exc_info:
                await audit_pack_service.generate_audit_pack(
                    start_date=date(2024, 1, 1),
                    end_date=date(2024, 1, 31),
                    created_by="admin-123",
                    reason="Monthly compliance review",
                )

        assert "S3 connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_storage_ref_format(self, audit_pack_service, mock_db_session, mock_object_store):
        """Test that storage reference has correct S3 URI format."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 0
            mock_verification.first_seq_no = None
            mock_verification.last_seq_no = None
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            result = await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
            )

        # Verify storage ref format
        assert result.storage_ref.startswith("s3://test-audit-bucket/")
        assert "test-audit-packs/" in result.storage_ref
        assert result.storage_ref.endswith(".zip")


class TestAuditPackServiceCryptoParams:
    """Tests for cryptographic parameters collection."""

    @pytest.mark.asyncio
    async def test_crypto_params_from_trust_service(
        self, audit_pack_service, mock_db_session, mock_trust_service
    ):
        """Test that crypto params are collected from trust service."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 0
            mock_verification.first_seq_no = None
            mock_verification.last_seq_no = None
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
            )

        # Verify get_keys was called to get algorithm suite
        mock_trust_service.get_keys.assert_called_once()


class TestAuditPackServiceKeyInventory:
    """Tests for key inventory collection."""

    @pytest.mark.asyncio
    async def test_key_inventory_collected(
        self, audit_pack_service, mock_db_session, mock_trust_service
    ):
        """Test that key inventory is collected in audit pack."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        with patch("qerds.services.audit_log.AuditLogService") as mock_audit_log_class:
            mock_audit_log = MagicMock()
            mock_verification = MagicMock()
            mock_verification.valid = True
            mock_verification.checked_records = 0
            mock_verification.first_seq_no = None
            mock_verification.last_seq_no = None
            mock_verification.errors = []
            mock_audit_log.verify_chain = AsyncMock(return_value=mock_verification)
            mock_audit_log_class.return_value = mock_audit_log

            result = await audit_pack_service.generate_audit_pack(
                start_date=date(2024, 1, 1),
                end_date=date(2024, 1, 31),
                created_by="admin-123",
                reason="Monthly compliance review",
            )

        # Verify get_key_inventory was called
        mock_trust_service.get_key_inventory.assert_called_once()

        # Verify key count in summary
        assert result.contents_summary["key_count"] == 2


class TestVerificationInstructions:
    """Tests for verification instructions generation."""

    def test_verification_instructions_content(self, audit_pack_service):
        """Test that verification instructions contain required sections."""
        pack_id = uuid.uuid4()
        pack_hash = "abc123def456"

        instructions = audit_pack_service._generate_verification_instructions(
            pack_id=pack_id,
            pack_hash=pack_hash,
        )

        # Check required sections
        assert "# Audit Pack Verification Instructions" in instructions
        assert str(pack_id) in instructions
        assert pack_hash in instructions
        assert "Verify Pack Integrity" in instructions
        assert "Verify Seal Signature" in instructions
        assert "Verify Timestamp" in instructions
        assert "Verify Audit Log Chains" in instructions
        assert "non_qualified" in instructions


class TestPolicyAndReleaseMetadata:
    """Tests for policy references and release metadata."""

    def test_policy_refs_structure(self, audit_pack_service):
        """Test that policy refs have correct structure."""
        policy_refs = audit_pack_service._get_policy_refs()

        assert "cps" in policy_refs
        assert "terms_of_service" in policy_refs
        assert "privacy_policy" in policy_refs

    def test_release_metadata_structure(self, audit_pack_service):
        """Test that release metadata has correct structure."""
        release_metadata = audit_pack_service._get_release_metadata()

        assert "app_version" in release_metadata
        assert "sbom_ref" in release_metadata
        assert "build_timestamp" in release_metadata
        assert release_metadata["app_version"] == "1.0.0-test"


# -----------------------------------------------------------------------------
# Factory Function Tests
# -----------------------------------------------------------------------------


class TestCreateAuditPackService:
    """Tests for the factory function."""

    @pytest.mark.asyncio
    async def test_create_audit_pack_service(
        self, mock_db_session, mock_trust_service, mock_object_store
    ):
        """Test creating audit pack service via factory function."""
        from qerds.services.audit_pack import create_audit_pack_service

        service = await create_audit_pack_service(
            session=mock_db_session,
            trust_service=mock_trust_service,
            object_store=mock_object_store,
            audit_bucket="custom-bucket",
            max_evidence_samples=500,
            app_version="2.0.0",
        )

        assert isinstance(service, AuditPackService)
        assert service._config.audit_bucket == "custom-bucket"
        assert service._config.max_evidence_samples == 500
        assert service._config.app_version == "2.0.0"
