"""Tests for the Conformity Package Service.

Tests cover:
- Conformity package generation with all content types
- Traceability matrix building (REQ-A04)
- Policy document collection
- Sealing and timestamping of packages
- Storage to object store
- Auditor guide generation
- Error handling

Run with: docker compose exec qerds-api pytest tests/test_conformity_package.py -v
"""

from __future__ import annotations

import io
import uuid
import zipfile
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from qerds.services.conformity_package import (
    POLICY_DOCUMENTS,
    REQUIREMENT_TRACEABILITY,
    ConformityPackageConfig,
    ConformityPackageContents,
    ConformityPackageService,
    ConformityPackageStorageError,
    PolicyDocumentInfo,
    SealedConformityPackage,
    TraceabilityEntry,
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

    # Mock get_key_lifecycle_events method
    trust_service.get_key_lifecycle_events = AsyncMock(return_value=[])

    return trust_service


@pytest.fixture
def mock_object_store():
    """Create a mock object store client."""
    object_store = MagicMock()
    object_store.ensure_bucket = MagicMock()
    object_store.upload = MagicMock()
    return object_store


@pytest.fixture
def conformity_package_config():
    """Create a conformity package configuration."""
    return ConformityPackageConfig(
        package_bucket="test-conformity-bucket",
        storage_prefix="test-packages/",
        max_evidence_samples=50,
        max_ceremony_events=100,
        app_version="1.0.0-test",
        sbom_ref="sbom/test-sbom.json",
    )


@pytest.fixture
def conformity_package_service(
    mock_db_session, mock_trust_service, mock_object_store, conformity_package_config, tmp_path
):
    """Create a conformity package service with mocked dependencies."""
    # Create test policy files
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    (policies_dir / "security-policy.md").write_text("# Security Policy\n\nTest content.")
    (policies_dir / "incident-policy.md").write_text("# Incident Policy\n\nTest content.")
    (policies_dir / "continuity-policy.md").write_text("# Continuity Policy\n\nTest content.")
    (policies_dir / "key-management-policy.md").write_text("# Key Management\n\nTest content.")
    (policies_dir / "evidence-management-policy.md").write_text("# Evidence Management\n\nTest.")
    (policies_dir / "privacy-policy.md").write_text("# Privacy Policy\n\nTest content.")

    cps_dir = policies_dir / "cps"
    cps_dir.mkdir()
    (cps_dir / "README.md").write_text("# CPS\n\nTest CPS.")

    # Update config to use tmp_path
    conformity_package_config.policies_path = "policies"

    return ConformityPackageService(
        session=mock_db_session,
        trust_service=mock_trust_service,
        object_store=mock_object_store,
        config=conformity_package_config,
        base_path=tmp_path,
    )


# -----------------------------------------------------------------------------
# ConformityPackageConfig Tests
# -----------------------------------------------------------------------------


class TestConformityPackageConfig:
    """Tests for ConformityPackageConfig dataclass."""

    def test_default_config_values(self):
        """Test that default config has sensible values."""
        config = ConformityPackageConfig()
        assert config.package_bucket == "qerds-conformity"
        assert config.storage_prefix == "conformity-packages/"
        assert config.max_evidence_samples == 100
        assert config.max_ceremony_events == 500
        assert config.app_version == "0.1.0"

    def test_custom_config_values(self, conformity_package_config):
        """Test that custom config values are applied."""
        assert conformity_package_config.package_bucket == "test-conformity-bucket"
        assert conformity_package_config.max_evidence_samples == 50


# -----------------------------------------------------------------------------
# TraceabilityEntry Tests
# -----------------------------------------------------------------------------


class TestTraceabilityEntry:
    """Tests for TraceabilityEntry dataclass."""

    def test_traceability_entry_creation(self):
        """Test creating a TraceabilityEntry."""
        entry = TraceabilityEntry(
            requirement_id="REQ-A01",
            title="Test Requirement",
            category="governance",
            modules=["module.path"],
            tests=["tests/test_file.py"],
            evidence=["evidence artifact"],
            implementation_status="implemented",
        )
        assert entry.requirement_id == "REQ-A01"
        assert entry.category == "governance"

    def test_traceability_entry_to_dict(self):
        """Test TraceabilityEntry serialization."""
        entry = TraceabilityEntry(
            requirement_id="REQ-B01",
            title="Evidence Requirement",
            category="evidence",
            modules=["qerds.services.evidence"],
            tests=["tests/test_evidence.py"],
            evidence=["sealed evidence objects"],
            implementation_status="implemented",
        )
        data = entry.to_dict()
        assert data["requirement_id"] == "REQ-B01"
        assert "qerds.services.evidence" in data["modules"]


# -----------------------------------------------------------------------------
# PolicyDocumentInfo Tests
# -----------------------------------------------------------------------------


class TestPolicyDocumentInfo:
    """Tests for PolicyDocumentInfo dataclass."""

    def test_policy_document_info_creation(self):
        """Test creating a PolicyDocumentInfo."""
        info = PolicyDocumentInfo(
            doc_id="security_policy",
            title="Security Policy",
            path="policies/security-policy.md",
            publication_status="internal",
            content_hash="abc123",
            last_modified=datetime.now(UTC),
        )
        assert info.doc_id == "security_policy"
        assert info.publication_status == "internal"

    def test_policy_document_info_to_dict(self):
        """Test PolicyDocumentInfo serialization."""
        now = datetime.now(UTC)
        info = PolicyDocumentInfo(
            doc_id="cps",
            title="CPS",
            path="policies/cps/README.md",
            publication_status="published",
            content_hash="def456",
            last_modified=now,
        )
        data = info.to_dict()
        assert data["doc_id"] == "cps"
        assert data["publication_status"] == "published"
        assert data["last_modified"] == now.isoformat()


# -----------------------------------------------------------------------------
# ConformityPackageContents Tests
# -----------------------------------------------------------------------------


class TestConformityPackageContents:
    """Tests for ConformityPackageContents dataclass."""

    def test_contents_creation(self):
        """Test creating ConformityPackageContents."""
        entry = TraceabilityEntry(
            requirement_id="REQ-A01",
            title="Test",
            category="test",
            modules=[],
            tests=[],
            evidence=[],
            implementation_status="not_implemented",
        )
        doc = PolicyDocumentInfo(
            doc_id="test",
            title="Test",
            path="test.md",
            publication_status="internal",
            content_hash="abc",
            last_modified=None,
        )
        contents = ConformityPackageContents(
            traceability_matrix=[entry],
            policy_documents=[doc],
            evidence_samples=[{"event_id": "evt-1"}],
            config_snapshots=[{"version": "v1.0"}],
            key_inventory={"total_keys": 2},
            key_ceremony_events=[],
            release_metadata={"app_version": "1.0.0"},
            system_info={"qualification_mode": "non_qualified"},
        )
        assert len(contents.traceability_matrix) == 1
        assert len(contents.policy_documents) == 1


# -----------------------------------------------------------------------------
# SealedConformityPackage Tests
# -----------------------------------------------------------------------------


class TestSealedConformityPackage:
    """Tests for SealedConformityPackage dataclass."""

    def test_sealed_package_creation(self):
        """Test creating a SealedConformityPackage."""
        package_id = uuid.uuid4()
        now = datetime.now(UTC)
        package = SealedConformityPackage(
            package_id=package_id,
            assessment_type="initial",
            created_at=now,
            created_by="admin-123",
            reason="Test package",
            contents_summary={"requirement_count": 50},
            package_hash="hash123",
            seal_signature="sig123",
            timestamp_token={"token_id": "tst-1"},
            storage_ref="s3://bucket/key",
            qualification_label="non_qualified",
        )
        assert package.package_id == package_id
        assert package.assessment_type == "initial"

    def test_sealed_package_to_dict(self):
        """Test SealedConformityPackage serialization."""
        package_id = uuid.uuid4()
        now = datetime.now(UTC)
        package = SealedConformityPackage(
            package_id=package_id,
            assessment_type="periodic",
            created_at=now,
            created_by="admin-456",
            reason="Periodic review",
            contents_summary={"requirement_count": 45},
            package_hash="hashxyz",
            seal_signature="sigxyz",
            timestamp_token={"token_id": "tst-2"},
            storage_ref="s3://bucket/key2",
            qualification_label="non_qualified",
        )
        data = package.to_dict()
        assert data["package_id"] == str(package_id)
        assert data["assessment_type"] == "periodic"
        assert data["created_at"] == now.isoformat()


# -----------------------------------------------------------------------------
# REQUIREMENT_TRACEABILITY Tests (REQ-A04)
# -----------------------------------------------------------------------------


class TestRequirementTraceability:
    """Tests for the requirement traceability constant."""

    def test_traceability_matrix_is_complete(self):
        """Test that the traceability matrix covers all expected requirements."""
        # All REQ-A through REQ-I requirements should be present
        expected_prefixes = [
            "REQ-A",
            "REQ-B",
            "REQ-C",
            "REQ-D",
            "REQ-E",
            "REQ-F",
            "REQ-G",
            "REQ-H",
            "REQ-I",
        ]
        for prefix in expected_prefixes:
            matching = [r for r in REQUIREMENT_TRACEABILITY if r.startswith(prefix)]
            assert len(matching) > 0, f"No requirements found with prefix {prefix}"

    def test_traceability_entries_have_required_fields(self):
        """Test that each entry has required fields."""
        for req_id, entry in REQUIREMENT_TRACEABILITY.items():
            assert "title" in entry, f"{req_id} missing title"
            assert "category" in entry, f"{req_id} missing category"
            assert "modules" in entry, f"{req_id} missing modules"
            assert "tests" in entry, f"{req_id} missing tests"
            assert "evidence" in entry, f"{req_id} missing evidence"

    def test_traceability_for_conformity_assessment(self):
        """Test that REQ-A02 (conformity assessment) is properly mapped."""
        assert "REQ-A02" in REQUIREMENT_TRACEABILITY
        entry = REQUIREMENT_TRACEABILITY["REQ-A02"]
        assert "qerds.services.conformity_package" in entry["modules"]
        assert any("test_conformity_package" in t for t in entry["tests"])

    def test_traceability_for_traceability_matrix(self):
        """Test that REQ-A04 (traceability matrix) is properly mapped."""
        assert "REQ-A04" in REQUIREMENT_TRACEABILITY
        entry = REQUIREMENT_TRACEABILITY["REQ-A04"]
        assert "REQUIREMENT_TRACEABILITY" in str(entry["modules"])


# -----------------------------------------------------------------------------
# POLICY_DOCUMENTS Tests
# -----------------------------------------------------------------------------


class TestPolicyDocuments:
    """Tests for the policy documents constant."""

    def test_all_required_policies_present(self):
        """Test that all required policy documents are defined."""
        required = [
            "cps",
            "security_policy",
            "incident_policy",
            "continuity_policy",
            "key_management_policy",
            "evidence_management_policy",
            "privacy_policy",
        ]
        for doc_id in required:
            assert doc_id in POLICY_DOCUMENTS, f"Missing policy: {doc_id}"

    def test_policy_entries_have_required_fields(self):
        """Test that each policy entry has required fields."""
        for doc_id, entry in POLICY_DOCUMENTS.items():
            assert "title" in entry, f"{doc_id} missing title"
            assert "path" in entry, f"{doc_id} missing path"
            assert "publication_status" in entry, f"{doc_id} missing publication_status"


# -----------------------------------------------------------------------------
# ConformityPackageService Tests
# -----------------------------------------------------------------------------


class TestConformityPackageService:
    """Tests for ConformityPackageService."""

    @pytest.mark.asyncio
    async def test_build_traceability_matrix(self, conformity_package_service):
        """Test building the traceability matrix."""
        matrix = await conformity_package_service._build_traceability_matrix()

        assert len(matrix) == len(REQUIREMENT_TRACEABILITY)
        assert all(isinstance(e, TraceabilityEntry) for e in matrix)

        # Check a specific entry
        a02_entries = [e for e in matrix if e.requirement_id == "REQ-A02"]
        assert len(a02_entries) == 1
        assert a02_entries[0].category == "governance"

    @pytest.mark.asyncio
    async def test_collect_policy_documents(self, conformity_package_service):
        """Test collecting policy document information."""
        docs = await conformity_package_service._collect_policy_documents()

        assert len(docs) == len(POLICY_DOCUMENTS)
        assert all(isinstance(d, PolicyDocumentInfo) for d in docs)

        # Check that content hashes were computed for existing files
        security_doc = next(d for d in docs if d.doc_id == "security_policy")
        assert security_doc.content_hash != ""

    @pytest.mark.asyncio
    async def test_collect_evidence_samples_empty_db(
        self, conformity_package_service, mock_db_session
    ):
        """Test collecting evidence samples when database is empty."""
        # Mock empty result
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result

        samples = await conformity_package_service._collect_evidence_samples()
        assert samples == []

    @pytest.mark.asyncio
    async def test_get_key_inventory(self, conformity_package_service):
        """Test getting key inventory."""
        inventory = await conformity_package_service._get_key_inventory()

        assert "total_keys" in inventory
        assert inventory["total_keys"] == 2

    @pytest.mark.asyncio
    async def test_get_release_metadata(self, conformity_package_service):
        """Test getting release metadata."""
        metadata = conformity_package_service._get_release_metadata()

        assert metadata["app_version"] == "1.0.0-test"
        assert metadata["sbom_ref"] == "sbom/test-sbom.json"
        assert "generated_at" in metadata

    @pytest.mark.asyncio
    async def test_get_system_info(self, conformity_package_service):
        """Test getting system info."""
        info = await conformity_package_service._get_system_info()

        assert info["qualification_mode"] == "non_qualified"
        assert "crypto_suite" in info
        assert info["crypto_suite"]["hash_algorithm"] == "sha384"

    @pytest.mark.asyncio
    async def test_generate_traceability_markdown(self, conformity_package_service):
        """Test generating human-readable traceability matrix."""
        matrix = await conformity_package_service._build_traceability_matrix()
        markdown = conformity_package_service._generate_traceability_markdown(matrix)

        assert "# Requirement Traceability Matrix" in markdown
        assert "REQ-A01" in markdown
        assert "REQ-A02" in markdown
        assert "## Matrix Overview" in markdown
        assert "## Detailed Entries" in markdown

    @pytest.mark.asyncio
    async def test_generate_auditor_guide(self, conformity_package_service):
        """Test generating auditor guide."""
        package_id = uuid.uuid4()
        guide = conformity_package_service._generate_auditor_guide(
            package_id=package_id,
            package_hash="abc123def456",
            assessment_type="initial",
        )

        assert "# Conformity Assessment Package - Auditor Guide" in guide
        assert str(package_id) in guide
        assert "abc123def456" in guide
        assert "initial" in guide
        assert "non_qualified" in guide

    @pytest.mark.asyncio
    async def test_build_manifest(self, conformity_package_service):
        """Test building the package manifest."""
        entry = TraceabilityEntry(
            requirement_id="REQ-A01",
            title="Test",
            category="test",
            modules=[],
            tests=[],
            evidence=[],
            implementation_status="not_implemented",
        )
        doc = PolicyDocumentInfo(
            doc_id="test",
            title="Test",
            path="test.md",
            publication_status="internal",
            content_hash="abc",
            last_modified=None,
        )
        contents = ConformityPackageContents(
            traceability_matrix=[entry],
            policy_documents=[doc],
            evidence_samples=[],
            config_snapshots=[],
            key_inventory={"total_keys": 0},
            key_ceremony_events=[],
            release_metadata={"app_version": "1.0.0"},
            system_info={"qualification_mode": "non_qualified"},
        )

        package_id = uuid.uuid4()
        now = datetime.now(UTC)

        manifest = conformity_package_service._build_manifest(
            package_id=package_id,
            assessment_type="initial",
            created_at=now,
            created_by="admin-123",
            reason="Test reason",
            contents=contents,
        )

        assert manifest["package_id"] == str(package_id)
        assert manifest["type"] == "conformity_assessment_package"
        assert manifest["assessment_type"] == "initial"
        assert "traceability_matrix" in manifest["contents"]
        assert manifest["statistics"]["requirement_count"] == 1

    @pytest.mark.asyncio
    async def test_generate_conformity_package(
        self, conformity_package_service, mock_db_session, mock_object_store
    ):
        """Test full package generation flow."""
        # Mock empty database results
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result

        package = await conformity_package_service.generate_conformity_package(
            assessment_type="initial",
            created_by="admin-123",
            reason="Test conformity assessment",
            include_evidence_samples=False,
            include_key_ceremonies=False,
        )

        assert isinstance(package, SealedConformityPackage)
        assert package.assessment_type == "initial"
        assert package.created_by == "admin-123"
        assert package.qualification_label == "non_qualified"
        assert package.contents_summary["requirement_count"] > 0

        # Verify seal and timestamp were called
        conformity_package_service._trust_service.seal.assert_called_once()
        conformity_package_service._trust_service.timestamp.assert_called_once()

        # Verify storage was called
        mock_object_store.ensure_bucket.assert_called_once()
        mock_object_store.upload.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_conformity_package_storage_error(
        self, conformity_package_service, mock_db_session, mock_object_store
    ):
        """Test package generation when storage fails."""
        # Mock empty database results
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result

        # Make upload raise an exception
        mock_object_store.upload.side_effect = Exception("Storage error")

        with pytest.raises(ConformityPackageStorageError) as exc_info:
            await conformity_package_service.generate_conformity_package(
                assessment_type="initial",
                created_by="admin-123",
                reason="Test conformity assessment",
            )

        assert "Storage error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_store_package_creates_zip(self, conformity_package_service, mock_object_store):
        """Test that package storage creates a proper ZIP archive."""
        captured_data = {}

        def capture_upload(bucket, key, data, content_type, metadata):
            captured_data["bucket"] = bucket
            captured_data["key"] = key
            captured_data["data"] = data
            captured_data["content_type"] = content_type
            captured_data["metadata"] = metadata

        mock_object_store.upload.side_effect = capture_upload

        entry = TraceabilityEntry(
            requirement_id="REQ-A01",
            title="Test",
            category="test",
            modules=[],
            tests=[],
            evidence=[],
            implementation_status="not_implemented",
        )
        doc = PolicyDocumentInfo(
            doc_id="test",
            title="Test",
            path="test.md",
            publication_status="internal",
            content_hash="abc",
            last_modified=None,
        )
        contents = ConformityPackageContents(
            traceability_matrix=[entry],
            policy_documents=[doc],
            evidence_samples=[],
            config_snapshots=[],
            key_inventory={"total_keys": 0},
            key_ceremony_events=[],
            release_metadata={"app_version": "1.0.0"},
            system_info={"qualification_mode": "non_qualified"},
        )

        # Mock seal and timestamp
        seal_result = MagicMock()
        seal_result.to_dict.return_value = {"seal_id": "test"}
        timestamp_result = MagicMock()
        timestamp_result.to_dict.return_value = {"token_id": "test"}

        package_id = uuid.uuid4()
        await conformity_package_service._store_package(
            package_id=package_id,
            manifest={"test": "manifest"},
            package_contents=contents,
            seal_data=seal_result,
            timestamp_token=timestamp_result,
            assessment_type="initial",
        )

        # Verify ZIP was created
        assert captured_data["content_type"] == "application/zip"

        # Verify ZIP contents
        zip_buffer = io.BytesIO(captured_data["data"])
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            names = zf.namelist()
            assert "manifest.json" in names
            assert "traceability_matrix.json" in names
            assert "traceability_matrix.md" in names
            assert "policy_documents/index.json" in names
            assert "seal.json" in names
            assert "timestamp.json" in names
            assert "auditor_guide.md" in names


# -----------------------------------------------------------------------------
# Integration-style Tests
# -----------------------------------------------------------------------------


class TestConformityPackageIntegration:
    """Integration-style tests for conformity packages."""

    @pytest.mark.asyncio
    async def test_full_package_generation_with_all_options(
        self, conformity_package_service, mock_db_session, mock_object_store
    ):
        """Test package generation with all options enabled."""
        # Mock empty database results
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result

        package = await conformity_package_service.generate_conformity_package(
            assessment_type="periodic",
            created_by="admin-xyz",
            reason="Periodic conformity review for QERDS certification",
            include_evidence_samples=True,
            include_key_ceremonies=True,
        )

        # Verify package structure
        assert package.assessment_type == "periodic"
        assert package.created_by == "admin-xyz"
        assert len(package.package_hash) == 64  # SHA-256 hex

        # Verify contents summary
        assert package.contents_summary["requirement_count"] == len(REQUIREMENT_TRACEABILITY)
        assert package.contents_summary["policy_document_count"] == len(POLICY_DOCUMENTS)

    @pytest.mark.asyncio
    async def test_package_qualification_label_from_trust_service(
        self, mock_db_session, mock_trust_service, mock_object_store, tmp_path
    ):
        """Test that qualification label comes from trust service."""
        # Set trust service to qualified mode
        mock_trust_service.mode.value = "qualified"

        config = ConformityPackageConfig()
        config.policies_path = "policies"

        # Create minimal policy files
        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "cps").mkdir()
        for _doc_id, doc_data in POLICY_DOCUMENTS.items():
            doc_path = tmp_path / doc_data["path"]
            doc_path.parent.mkdir(parents=True, exist_ok=True)
            doc_path.write_text("# Test\n")

        service = ConformityPackageService(
            session=mock_db_session,
            trust_service=mock_trust_service,
            object_store=mock_object_store,
            config=config,
            base_path=tmp_path,
        )

        # Mock empty database results
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result

        package = await service.generate_conformity_package(
            assessment_type="initial",
            created_by="admin-123",
            reason="Test qualified mode package",
        )

        assert package.qualification_label == "qualified"


# -----------------------------------------------------------------------------
# Factory Function Tests
# -----------------------------------------------------------------------------


class TestCreateConformityPackageService:
    """Tests for the factory function."""

    @pytest.mark.asyncio
    async def test_create_conformity_package_service(
        self, mock_db_session, mock_trust_service, mock_object_store
    ):
        """Test factory function creates service correctly."""
        from qerds.services.conformity_package import create_conformity_package_service

        service = await create_conformity_package_service(
            session=mock_db_session,
            trust_service=mock_trust_service,
            object_store=mock_object_store,
            package_bucket="custom-bucket",
            max_evidence_samples=200,
            app_version="2.0.0",
        )

        assert isinstance(service, ConformityPackageService)
        assert service._config.package_bucket == "custom-bucket"
        assert service._config.max_evidence_samples == 200
        assert service._config.app_version == "2.0.0"
