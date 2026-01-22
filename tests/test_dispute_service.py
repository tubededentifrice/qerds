"""Tests for Dispute Timeline Reconstruction Service.

Tests cover:
- Timeline reconstruction with events in chronological order
- Evidence verification status
- GDPR-compliant redaction at various levels
- Disclosure package creation with integrity hashing
- Party and content information redaction

Run with: docker compose exec qerds-api pytest tests/test_dispute_service.py -v
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from qerds.services.dispute import (
    ContentInfo,
    DeliveryNotFoundError,
    DisclosurePackage,
    DisputeService,
    DisputeTimeline,
    EvidenceVerification,
    PartyInfo,
    RedactionLevel,
    TimelineEvent,
    VerificationStatus,
)

# -----------------------------------------------------------------------------
# Test Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_party_natural():
    """Create a mock natural person party."""
    party = MagicMock()
    party.party_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440001")
    party.party_type = MagicMock()
    party.party_type.value = "natural_person"
    party.display_name = "John Doe"
    party.email = "john.doe@example.com"
    return party


@pytest.fixture
def mock_party_legal():
    """Create a mock legal person party."""
    party = MagicMock()
    party.party_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440002")
    party.party_type = MagicMock()
    party.party_type.value = "legal_person"
    party.display_name = "Acme Corporation"
    party.email = "legal@acme.com"
    return party


@pytest.fixture
def mock_content_object():
    """Create a mock content object."""
    content = MagicMock()
    content.content_object_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440010")
    content.sha256 = "a" * 64
    content.size_bytes = 1024
    content.mime_type = "application/pdf"
    content.original_filename = "contract.pdf"
    return content


@pytest.fixture
def mock_evidence_object():
    """Create a mock evidence object."""
    eo = MagicMock()
    eo.evidence_object_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440020")
    eo.canonical_payload_digest = "b" * 64
    eo.provider_attestation_blob_ref = "s3://evidence/seal-001.cms"
    eo.time_attestation_blob_ref = "s3://evidence/timestamp-001.tst"
    eo.qualification_label = MagicMock()
    eo.qualification_label.value = "non_qualified"
    return eo


@pytest.fixture
def mock_evidence_event(mock_evidence_object):
    """Create a mock evidence event."""
    event = MagicMock()
    event.event_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440030")
    event.event_type = MagicMock()
    event.event_type.value = "evt_deposited"
    event.event_time = datetime.now(UTC)
    event.actor_type = MagicMock()
    event.actor_type.value = "sender"
    event.actor_ref = "party-550e8400-e29b-41d4-a716-446655440001"
    event.policy_snapshot_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440040")
    event.event_metadata = {
        "actor_identification": {
            "ip_address": "192.168.1.100",
            "session_ref": "sess-abc123",
        }
    }
    event.evidence_objects = [mock_evidence_object]
    return event


@pytest.fixture
def mock_delivery(mock_party_natural, mock_party_legal, mock_content_object, mock_evidence_event):
    """Create a mock delivery with all relationships."""
    delivery = MagicMock()
    delivery.delivery_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
    delivery.state = MagicMock()
    delivery.state.value = "deposited"
    delivery.jurisdiction_profile = "fr_lre"
    delivery.sender_party = mock_party_natural
    delivery.recipient_party = mock_party_legal
    delivery.content_objects = [mock_content_object]
    delivery.evidence_events = [mock_evidence_event]
    return delivery


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    session = AsyncMock()
    return session


# -----------------------------------------------------------------------------
# RedactionLevel Tests
# -----------------------------------------------------------------------------


class TestRedactionLevel:
    """Tests for RedactionLevel enum."""

    def test_all_levels_defined(self):
        """Test that all expected redaction levels are defined."""
        expected = ["none", "minimal", "standard", "full"]
        actual = [level.value for level in RedactionLevel]
        assert set(expected) == set(actual)

    def test_level_from_string(self):
        """Test creating RedactionLevel from string."""
        assert RedactionLevel("none") == RedactionLevel.NONE
        assert RedactionLevel("minimal") == RedactionLevel.MINIMAL
        assert RedactionLevel("standard") == RedactionLevel.STANDARD
        assert RedactionLevel("full") == RedactionLevel.FULL

    def test_invalid_level_raises_error(self):
        """Test that invalid level raises ValueError."""
        with pytest.raises(ValueError):
            RedactionLevel("invalid")


# -----------------------------------------------------------------------------
# VerificationStatus Tests
# -----------------------------------------------------------------------------


class TestVerificationStatus:
    """Tests for VerificationStatus enum."""

    def test_all_statuses_defined(self):
        """Test that all expected verification statuses are defined."""
        expected = ["valid", "invalid", "not_sealed", "missing"]
        actual = [status.value for status in VerificationStatus]
        assert set(expected) == set(actual)


# -----------------------------------------------------------------------------
# EvidenceVerification Tests
# -----------------------------------------------------------------------------


class TestEvidenceVerification:
    """Tests for EvidenceVerification dataclass."""

    def test_to_dict(self):
        """Test EvidenceVerification serialization."""
        verification = EvidenceVerification(
            evidence_object_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440020"),
            status=VerificationStatus.VALID,
            content_hash_matches=True,
            has_provider_attestation=True,
            has_time_attestation=True,
            qualification_label="qualified",
            verification_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            errors=[],
        )

        result = verification.to_dict()

        assert result["evidence_object_id"] == "550e8400-e29b-41d4-a716-446655440020"
        assert result["status"] == "valid"
        assert result["content_hash_matches"] is True
        assert result["has_provider_attestation"] is True
        assert result["qualification_label"] == "qualified"
        assert result["errors"] == []

    def test_to_dict_with_errors(self):
        """Test EvidenceVerification with errors."""
        verification = EvidenceVerification(
            evidence_object_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440020"),
            status=VerificationStatus.NOT_SEALED,
            content_hash_matches=None,
            has_provider_attestation=False,
            has_time_attestation=False,
            qualification_label="non_qualified",
            verification_time=datetime.now(UTC),
            errors=["No cryptographic attestations present"],
        )

        result = verification.to_dict()

        assert result["status"] == "not_sealed"
        assert result["content_hash_matches"] is None
        assert len(result["errors"]) == 1


# -----------------------------------------------------------------------------
# PartyInfo Tests
# -----------------------------------------------------------------------------


class TestPartyInfo:
    """Tests for PartyInfo dataclass."""

    def test_to_dict(self):
        """Test PartyInfo serialization."""
        party_info = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440001"),
            party_type="natural_person",
            display_name="John Doe",
            email_hash="abcd1234",
            identity_ref="party-001",
        )

        result = party_info.to_dict()

        assert result["party_id"] == "550e8400-e29b-41d4-a716-446655440001"
        assert result["party_type"] == "natural_person"
        assert result["display_name"] == "John Doe"
        assert result["email_hash"] == "abcd1234"

    def test_to_dict_with_none_values(self):
        """Test PartyInfo with None values."""
        party_info = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440001"),
            party_type="natural_person",
            display_name="[REDACTED]",
            email_hash=None,
            identity_ref=None,
        )

        result = party_info.to_dict()

        assert result["display_name"] == "[REDACTED]"
        assert result["email_hash"] is None
        assert result["identity_ref"] is None


# -----------------------------------------------------------------------------
# ContentInfo Tests
# -----------------------------------------------------------------------------


class TestContentInfo:
    """Tests for ContentInfo dataclass."""

    def test_to_dict(self):
        """Test ContentInfo serialization."""
        content_info = ContentInfo(
            content_object_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440010"),
            sha256="a" * 64,
            size_bytes=2048,
            mime_type="application/pdf",
            original_filename="document.pdf",
        )

        result = content_info.to_dict()

        assert result["content_object_id"] == "550e8400-e29b-41d4-a716-446655440010"
        assert len(result["sha256"]) == 64
        assert result["size_bytes"] == 2048
        assert result["mime_type"] == "application/pdf"


# -----------------------------------------------------------------------------
# TimelineEvent Tests
# -----------------------------------------------------------------------------


class TestTimelineEvent:
    """Tests for TimelineEvent dataclass."""

    def test_to_dict(self):
        """Test TimelineEvent serialization."""
        verification = EvidenceVerification(
            evidence_object_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440020"),
            status=VerificationStatus.VALID,
            content_hash_matches=True,
            has_provider_attestation=True,
            has_time_attestation=True,
            qualification_label="qualified",
            verification_time=datetime.now(UTC),
            errors=[],
        )

        event = TimelineEvent(
            event_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440030"),
            event_type="evt_deposited",
            event_time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            actor_type="sender",
            actor_ref="party-001",
            description="Content deposited by sender",
            evidence_verifications=[verification],
            event_metadata={"key": "value"},
            policy_snapshot_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440040"),
        )

        result = event.to_dict()

        assert result["event_id"] == "550e8400-e29b-41d4-a716-446655440030"
        assert result["event_type"] == "evt_deposited"
        assert result["actor_type"] == "sender"
        assert result["description"] == "Content deposited by sender"
        assert len(result["evidence_verifications"]) == 1
        assert result["event_metadata"]["key"] == "value"


# -----------------------------------------------------------------------------
# DisputeTimeline Tests
# -----------------------------------------------------------------------------


class TestDisputeTimeline:
    """Tests for DisputeTimeline dataclass."""

    def test_to_dict(self):
        """Test DisputeTimeline serialization."""
        sender = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440001"),
            party_type="natural_person",
            display_name="John Doe",
            email_hash="abcd1234",
            identity_ref="party-001",
        )
        recipient = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440002"),
            party_type="legal_person",
            display_name="Acme Corp",
            email_hash="efgh5678",
            identity_ref="party-002",
        )

        timeline = DisputeTimeline(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            delivery_state="deposited",
            jurisdiction_profile="eidas",
            sender=sender,
            recipient=recipient,
            content_objects=[],
            events=[],
            policy_snapshots=[uuid.UUID("550e8400-e29b-41d4-a716-446655440040")],
            generated_at=datetime.now(UTC),
            generated_by="admin-001",
            redaction_level=RedactionLevel.STANDARD,
            verification_summary={"valid": 0, "invalid": 0, "not_sealed": 0, "missing": 0},
        )

        result = timeline.to_dict()

        assert result["delivery_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["delivery_state"] == "deposited"
        assert result["jurisdiction_profile"] == "eidas"
        assert result["sender"]["display_name"] == "John Doe"
        assert result["recipient"]["display_name"] == "Acme Corp"
        assert result["redaction_level"] == "standard"


# -----------------------------------------------------------------------------
# DisputeService Tests
# -----------------------------------------------------------------------------


class TestDisputeService:
    """Tests for DisputeService."""

    @pytest.mark.asyncio
    async def test_reconstruct_timeline_not_found(self, mock_db_session):
        """Test that DeliveryNotFoundError is raised for missing delivery."""
        # Setup mock to return None (delivery not found)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        service = DisputeService(mock_db_session)

        with pytest.raises(DeliveryNotFoundError) as exc_info:
            await service.reconstruct_timeline(
                delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
                generated_by="admin-001",
            )

        assert "not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_reconstruct_timeline_success(self, mock_db_session, mock_delivery):
        """Test successful timeline reconstruction."""
        # Setup mock to return delivery
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        service = DisputeService(mock_db_session)

        timeline = await service.reconstruct_timeline(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            generated_by="admin-001",
            redaction_level=RedactionLevel.NONE,
        )

        assert timeline.delivery_id == mock_delivery.delivery_id
        assert timeline.delivery_state == "deposited"
        assert timeline.jurisdiction_profile == "fr_lre"
        assert len(timeline.events) == 1
        assert timeline.redaction_level == RedactionLevel.NONE

    @pytest.mark.asyncio
    async def test_reconstruct_timeline_with_verification(self, mock_db_session, mock_delivery):
        """Test timeline reconstruction with evidence verification."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        service = DisputeService(mock_db_session)

        timeline = await service.reconstruct_timeline(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            generated_by="admin-001",
            verify_evidence=True,
        )

        # Should have verification results for evidence objects
        assert len(timeline.events) == 1
        event = timeline.events[0]
        assert len(event.evidence_verifications) == 1
        verification = event.evidence_verifications[0]
        assert verification.status == VerificationStatus.VALID
        assert verification.has_provider_attestation is True
        assert verification.has_time_attestation is True

    @pytest.mark.asyncio
    async def test_reconstruct_timeline_redaction_full(self, mock_db_session, mock_delivery):
        """Test timeline reconstruction with full redaction."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        service = DisputeService(mock_db_session)

        timeline = await service.reconstruct_timeline(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            generated_by="admin-001",
            redaction_level=RedactionLevel.FULL,
        )

        # Party names should be redacted
        assert timeline.sender.display_name == "[REDACTED]"
        assert timeline.recipient.display_name == "[REDACTED]"
        # Actor ref should be redacted
        assert timeline.events[0].actor_ref == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_reconstruct_timeline_redaction_standard(self, mock_db_session, mock_delivery):
        """Test timeline reconstruction with standard GDPR redaction."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        service = DisputeService(mock_db_session)

        timeline = await service.reconstruct_timeline(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            generated_by="admin-001",
            redaction_level=RedactionLevel.STANDARD,
        )

        # Names should be pseudonymized (hash-based)
        assert timeline.sender.display_name.startswith("Party-")
        assert len(timeline.sender.display_name) > 6  # "Party-" + hash
        # Actor ref should be pseudonymized
        assert timeline.events[0].actor_ref.startswith("actor-")

    @pytest.mark.asyncio
    async def test_create_disclosure_package(self, mock_db_session, mock_delivery):
        """Test disclosure package creation."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_delivery
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        service = DisputeService(mock_db_session)

        package = await service.create_disclosure_package(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            exported_by="admin-001",
            export_reason="Court order reference XYZ-123",
            redaction_level=RedactionLevel.STANDARD,
        )

        assert package.delivery_id == mock_delivery.delivery_id
        assert package.export_reason == "Court order reference XYZ-123"
        assert package.exported_by == "admin-001"
        # Package hash should be a valid SHA-256
        assert len(package.package_hash) == 64
        # Integrity manifest should contain component hashes
        assert "delivery_metadata" in package.integrity_manifest
        assert "content_objects" in package.integrity_manifest
        assert "parties" in package.integrity_manifest


# -----------------------------------------------------------------------------
# Service Helper Method Tests
# -----------------------------------------------------------------------------


class TestDisputeServiceHelpers:
    """Tests for DisputeService helper methods."""

    def test_build_party_info_no_redaction(self, mock_party_natural, mock_db_session):
        """Test party info building with no redaction."""
        service = DisputeService(mock_db_session)

        result = service._build_party_info(mock_party_natural, RedactionLevel.NONE)

        assert result.display_name == "John Doe"
        assert result.email_hash is not None
        # Email hash should be consistent
        expected_hash = hashlib.sha256(b"john.doe@example.com").hexdigest()[:16]
        assert result.email_hash == expected_hash

    def test_build_party_info_full_redaction(self, mock_party_natural, mock_db_session):
        """Test party info building with full redaction."""
        service = DisputeService(mock_db_session)

        result = service._build_party_info(mock_party_natural, RedactionLevel.FULL)

        assert result.display_name == "[REDACTED]"
        assert result.email_hash is None
        assert result.identity_ref == "[REDACTED]"

    def test_build_content_info_no_redaction(self, mock_content_object, mock_db_session):
        """Test content info building with no redaction."""
        service = DisputeService(mock_db_session)

        result = service._build_content_info(mock_content_object, RedactionLevel.NONE)

        assert result.original_filename == "contract.pdf"
        assert result.sha256 == "a" * 64
        assert result.size_bytes == 1024

    def test_build_content_info_standard_redaction(self, mock_content_object, mock_db_session):
        """Test content info building with standard redaction."""
        service = DisputeService(mock_db_session)

        result = service._build_content_info(mock_content_object, RedactionLevel.STANDARD)

        # Filename should be redacted but keep extension
        assert result.original_filename == "document.pdf"

    def test_build_content_info_full_redaction(self, mock_content_object, mock_db_session):
        """Test content info building with full redaction."""
        service = DisputeService(mock_db_session)

        result = service._build_content_info(mock_content_object, RedactionLevel.FULL)

        assert result.original_filename == "[REDACTED]"

    def test_verify_evidence_object_valid(self, mock_evidence_object, mock_db_session):
        """Test verification of valid evidence object."""
        service = DisputeService(mock_db_session)

        result = service._verify_evidence_object(mock_evidence_object)

        assert result.status == VerificationStatus.VALID
        assert result.has_provider_attestation is True
        assert result.has_time_attestation is True
        assert result.qualification_label == "non_qualified"

    def test_verify_evidence_object_not_sealed(self, mock_db_session):
        """Test verification of unsealed evidence object."""
        eo = MagicMock()
        eo.evidence_object_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440020")
        eo.canonical_payload_digest = "b" * 64
        eo.provider_attestation_blob_ref = None
        eo.time_attestation_blob_ref = None
        eo.qualification_label = MagicMock()
        eo.qualification_label.value = "non_qualified"

        service = DisputeService(mock_db_session)

        result = service._verify_evidence_object(eo)

        assert result.status == VerificationStatus.NOT_SEALED
        assert result.has_provider_attestation is False
        assert result.has_time_attestation is False
        assert len(result.errors) > 0

    def test_redact_metadata_none(self, mock_db_session):
        """Test metadata redaction with no redaction level."""
        service = DisputeService(mock_db_session)
        metadata = {
            "ip_address": "192.168.1.100",
            "session_ref": "sess-abc",
            "some_value": "keep",
        }

        result = service._redact_metadata(metadata, RedactionLevel.NONE)

        assert result["ip_address"] == "192.168.1.100"
        assert result["session_ref"] == "sess-abc"
        assert result["some_value"] == "keep"

    def test_redact_metadata_standard(self, mock_db_session):
        """Test metadata redaction with standard level."""
        service = DisputeService(mock_db_session)
        metadata = {
            "ip_address": "192.168.1.100",
            "session_ref": "sess-abc",
            "some_value": "keep",
        }

        result = service._redact_metadata(metadata, RedactionLevel.STANDARD)

        # Sensitive fields should be hashed
        assert result["ip_address"] != "192.168.1.100"
        assert len(result["ip_address"]) == 12  # Hash prefix length
        # Non-sensitive fields should be kept
        assert result["some_value"] == "keep"

    def test_redact_metadata_full(self, mock_db_session):
        """Test metadata redaction with full level."""
        service = DisputeService(mock_db_session)
        metadata = {
            "ip_address": "192.168.1.100",
            "session_ref": "sess-abc",
            "some_value": "keep",
        }

        result = service._redact_metadata(metadata, RedactionLevel.FULL)

        assert result["ip_address"] == "[REDACTED]"
        assert result["session_ref"] == "[REDACTED]"
        # Non-sensitive fields still kept
        assert result["some_value"] == "keep"

    def test_get_event_description_known_type(self, mock_db_session):
        """Test event description for known event types."""
        service = DisputeService(mock_db_session)

        assert service._get_event_description("evt_deposited") == "Content deposited by sender"
        assert service._get_event_description("evt_accepted") == "Delivery accepted by recipient"
        expected = "Delivery expired (acceptance deadline passed)"
        assert service._get_event_description("evt_expired") == expected

    def test_get_event_description_unknown_type(self, mock_db_session):
        """Test event description for unknown event type."""
        service = DisputeService(mock_db_session)

        result = service._get_event_description("unknown_event")

        assert "Event:" in result
        assert "unknown_event" in result


# -----------------------------------------------------------------------------
# Disclosure Package Tests
# -----------------------------------------------------------------------------


class TestDisclosurePackage:
    """Tests for DisclosurePackage dataclass."""

    def test_to_dict(self):
        """Test DisclosurePackage serialization."""
        sender = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440001"),
            party_type="natural_person",
            display_name="Party-abc123",
            email_hash="abcd1234",
            identity_ref="ref-abc123",
        )
        recipient = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440002"),
            party_type="legal_person",
            display_name="Party-def456",
            email_hash="efgh5678",
            identity_ref="ref-def456",
        )

        timeline = DisputeTimeline(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            delivery_state="deposited",
            jurisdiction_profile="fr_lre",
            sender=sender,
            recipient=recipient,
            content_objects=[],
            events=[],
            policy_snapshots=[],
            generated_at=datetime.now(UTC),
            generated_by="admin-001",
            redaction_level=RedactionLevel.STANDARD,
            verification_summary={"valid": 0, "invalid": 0, "not_sealed": 0, "missing": 0},
        )

        package = DisclosurePackage(
            package_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440099"),
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            timeline=timeline,
            export_reason="Court order XYZ-123",
            exported_at=datetime.now(UTC),
            exported_by="admin-001",
            package_hash="c" * 64,
            integrity_manifest={"delivery_metadata": "d" * 64},
        )

        result = package.to_dict()

        assert result["package_id"] == "550e8400-e29b-41d4-a716-446655440099"
        assert result["delivery_id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert result["export_reason"] == "Court order XYZ-123"
        assert len(result["package_hash"]) == 64
        assert "timeline" in result
        assert result["timeline"]["redaction_level"] == "standard"


# -----------------------------------------------------------------------------
# Integration-Style Tests
# -----------------------------------------------------------------------------


class TestDisputeServiceIntegration:
    """Integration-style tests for DisputeService."""

    @pytest.mark.asyncio
    async def test_timeline_events_are_chronological(self, mock_db_session):
        """Test that timeline events are returned in chronological order."""
        # Create events with different times
        now = datetime.now(UTC)
        events = []
        for i, event_type in enumerate(["evt_deposited", "evt_notification_sent", "evt_accepted"]):
            event = MagicMock()
            event.event_id = uuid.uuid4()
            event.event_type = MagicMock()
            event.event_type.value = event_type
            event.event_time = now + timedelta(hours=i)  # Sequential times
            event.actor_type = MagicMock()
            event.actor_type.value = "sender"
            event.actor_ref = "party-001"
            event.policy_snapshot_id = None
            event.event_metadata = {}
            event.evidence_objects = []
            events.append(event)

        # Shuffle events to test sorting
        import random

        shuffled_events = events.copy()
        random.shuffle(shuffled_events)

        # Create mock delivery
        delivery = MagicMock()
        delivery.delivery_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
        delivery.state = MagicMock()
        delivery.state.value = "accepted"
        delivery.jurisdiction_profile = "eidas"
        delivery.sender_party = MagicMock()
        delivery.sender_party.party_id = uuid.uuid4()
        delivery.sender_party.party_type = MagicMock()
        delivery.sender_party.party_type.value = "natural_person"
        delivery.sender_party.display_name = "Sender"
        delivery.sender_party.email = "sender@test.com"
        delivery.recipient_party = MagicMock()
        delivery.recipient_party.party_id = uuid.uuid4()
        delivery.recipient_party.party_type = MagicMock()
        delivery.recipient_party.party_type.value = "legal_person"
        delivery.recipient_party.display_name = "Recipient"
        delivery.recipient_party.email = "recipient@test.com"
        delivery.content_objects = []
        delivery.evidence_events = shuffled_events

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = delivery
        mock_db_session.execute = AsyncMock(return_value=mock_result)

        service = DisputeService(mock_db_session)
        timeline = await service.reconstruct_timeline(
            delivery_id=delivery.delivery_id,
            generated_by="admin-001",
        )

        # Verify events are in chronological order
        assert len(timeline.events) == 3
        assert timeline.events[0].event_type == "evt_deposited"
        assert timeline.events[1].event_type == "evt_notification_sent"
        assert timeline.events[2].event_type == "evt_accepted"

    def test_integrity_manifest_is_deterministic(self, mock_db_session):
        """Test that integrity manifest produces consistent hashes."""
        sender = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440001"),
            party_type="natural_person",
            display_name="Test User",
            email_hash="abcd1234",
            identity_ref="party-001",
        )
        recipient = PartyInfo(
            party_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440002"),
            party_type="legal_person",
            display_name="Test Corp",
            email_hash="efgh5678",
            identity_ref="party-002",
        )

        timeline = DisputeTimeline(
            delivery_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000"),
            delivery_state="deposited",
            jurisdiction_profile="eidas",
            sender=sender,
            recipient=recipient,
            content_objects=[],
            events=[],
            policy_snapshots=[],
            generated_at=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            generated_by="admin-001",
            redaction_level=RedactionLevel.STANDARD,
            verification_summary={"valid": 0, "invalid": 0, "not_sealed": 0, "missing": 0},
        )

        service = DisputeService(mock_db_session)

        # Generate manifest twice
        manifest1 = service._build_integrity_manifest(timeline)
        manifest2 = service._build_integrity_manifest(timeline)

        # Hashes should be identical
        assert manifest1 == manifest2
        assert manifest1["delivery_metadata"] == manifest2["delivery_metadata"]
        assert manifest1["parties"] == manifest2["parties"]
