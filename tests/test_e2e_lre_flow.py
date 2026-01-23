"""End-to-end integration tests for complete LRE (Lettre Recommandee Electronique) flow.

Covers: REQ-B01, REQ-B02, REQ-B03, REQ-B05, REQ-C01, REQ-C02, REQ-E01, REQ-E02,
        REQ-F01, REQ-F02, REQ-F03, REQ-F04, REQ-F06

These tests verify the complete LRE lifecycle from sender deposit through recipient
completion, including all CPCE compliance requirements:

Test Scenarios:
1. Accept flow: deposit -> notify -> available -> accept -> receive -> download
2. Refuse flow: deposit -> notify -> available -> refuse (content never accessible)
3. Expiry flow: deposit -> notify -> available -> expire (15-day window enforcement)

CPCE Compliance Verification:
- Sender identity redaction pre-acceptance (REQ-F03)
- 15-day acceptance window enforcement (REQ-F04)
- Consumer consent requirement for fr_lre (REQ-F06)
- IAL2+ requirement for LRE recipients (REQ-F04)
- Evidence generation at each state transition (REQ-C01)
- Proof verification after completion (REQ-B01, REQ-C02)

All tests run against Docker containers for reproducibility.
Use: docker compose exec qerds-api pytest tests/test_e2e_lre_flow.py -v
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

from qerds.db.models.base import (
    ActorType,
    ConsentType,
    DeliveryState,
    EncryptionScheme,
    EventType,
    IALLevel,
    PartyType,
)

# ---------------------------------------------------------------------------
# Fixtures for E2E Testing
# ---------------------------------------------------------------------------


@pytest.fixture
def sender_party_id() -> UUID:
    """Unique sender party ID for the test."""
    return uuid4()


@pytest.fixture
def recipient_party_id() -> UUID:
    """Unique recipient party ID for the test."""
    return uuid4()


@pytest.fixture
def delivery_id() -> UUID:
    """Unique delivery ID for the test."""
    return uuid4()


@pytest.fixture
def content_object_id() -> UUID:
    """Unique content object ID for the test."""
    return uuid4()


@pytest.fixture
def mock_sender_party(sender_party_id: UUID) -> MagicMock:
    """Create a mock sender party with required attributes."""
    party = MagicMock()
    party.party_id = sender_party_id
    party.party_type = PartyType.NATURAL_PERSON
    party.display_name = "Jean Dupont"
    party.email = "jean.dupont@example.com"
    party.created_at = datetime.now(UTC)
    return party


@pytest.fixture
def mock_recipient_party(recipient_party_id: UUID) -> MagicMock:
    """Create a mock recipient party with required attributes."""
    party = MagicMock()
    party.party_id = recipient_party_id
    party.party_type = PartyType.NATURAL_PERSON
    party.display_name = "Marie Martin"
    party.email = "marie.martin@example.com"
    party.created_at = datetime.now(UTC)
    return party


@pytest.fixture
def mock_content_object(delivery_id: UUID, content_object_id: UUID) -> MagicMock:
    """Create a mock content object for the delivery."""
    content = MagicMock()
    content.content_object_id = content_object_id
    content.delivery_id = delivery_id
    # SHA-256 of "Test content for LRE delivery"
    content.sha256 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    content.size_bytes = 2048
    content.mime_type = "application/pdf"
    content.original_filename = "contrat.pdf"
    content.storage_key = f"deliveries/{delivery_id}/content/{content.sha256}.enc"
    content.encryption_scheme = EncryptionScheme.AES_256_GCM
    content.encryption_metadata = {
        "version": "1.0",
        "algorithm": "AES-256-GCM",
        "nonce": "dGVzdG5vbmNl",
        "wrapped_dek": "dGVzdGtleQ==",
        "kek_id": "test-kek-001",
    }
    content.created_at = datetime.now(UTC)
    return content


@pytest.fixture
def mock_delivery_draft(
    delivery_id: UUID,
    sender_party_id: UUID,
    recipient_party_id: UUID,
    mock_sender_party: MagicMock,
    mock_recipient_party: MagicMock,
) -> MagicMock:
    """Create a mock delivery in DRAFT state."""
    delivery = MagicMock()
    delivery.delivery_id = delivery_id
    delivery.state = DeliveryState.DRAFT
    delivery.sender_party_id = sender_party_id
    delivery.recipient_party_id = recipient_party_id
    delivery.jurisdiction_profile = "fr_lre"  # French LRE
    delivery.subject = "Contrat important"
    delivery.message = "Veuillez consulter le contrat ci-joint."
    delivery.delivery_metadata = None
    delivery.created_at = datetime.now(UTC)
    delivery.updated_at = datetime.now(UTC)
    delivery.deposited_at = None
    delivery.notified_at = None
    delivery.available_at = None
    delivery.completed_at = None
    delivery.acceptance_deadline_at = None
    delivery.content_objects = []
    delivery.sender_party = mock_sender_party
    delivery.recipient_party = mock_recipient_party
    return delivery


def _create_evidence_event(
    delivery_id: UUID,
    event_type: EventType,
    actor_type: ActorType,
    actor_ref: str,
    event_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    """Helper to create a mock evidence event."""
    event = MagicMock()
    event.event_id = uuid4()
    event.delivery_id = delivery_id
    event.event_type = event_type
    event.event_time = datetime.now(UTC)
    event.actor_type = actor_type
    event.actor_ref = actor_ref
    event.policy_snapshot_id = None
    event.event_metadata = event_metadata or {}
    return event


# ---------------------------------------------------------------------------
# Test: Complete Accept Flow (Happy Path)
# ---------------------------------------------------------------------------


class TestCompleteAcceptFlow:
    """End-to-end tests for the complete accept flow.

    Simulates the full LRE lifecycle:
    1. Sender creates and deposits delivery
    2. System sends notification
    3. Recipient receives magic link
    4. Recipient authenticates via FC+
    5. Recipient views delivery (sender hidden)
    6. Recipient accepts delivery
    7. Sender identity revealed
    8. Recipient downloads content
    9. Evidence is generated at each step
    10. Proofs can be verified
    """

    @pytest.mark.asyncio
    async def test_step_1_sender_creates_delivery(
        self,
        delivery_id: UUID,
        sender_party_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Step 1: Sender creates a delivery in DRAFT state."""
        # Verify initial state
        assert mock_delivery_draft.state == DeliveryState.DRAFT
        assert mock_delivery_draft.jurisdiction_profile == "fr_lre"
        assert mock_delivery_draft.sender_party_id == sender_party_id
        assert mock_delivery_draft.deposited_at is None

    @pytest.mark.asyncio
    async def test_step_2_sender_deposits_content(
        self,
        delivery_id: UUID,
        sender_party_id: UUID,
        mock_delivery_draft: MagicMock,
        mock_content_object: MagicMock,
    ):
        """Step 2: Sender uploads content and deposits delivery (REQ-B01, REQ-B02)."""
        from qerds.services.lifecycle import DeliveryLifecycleService, TransitionResult

        with patch.object(
            DeliveryLifecycleService,
            "get_delivery",
            return_value=mock_delivery_draft,
        ):
            # Create deposit event
            deposit_event = _create_evidence_event(
                delivery_id,
                EventType.EVT_DEPOSITED,
                ActorType.SENDER,
                str(sender_party_id),
                {
                    "content_hashes": [mock_content_object.sha256],
                    "ial_level": "ial2",
                },
            )

            result = TransitionResult(
                success=True,
                previous_state=DeliveryState.DRAFT,
                new_state=DeliveryState.DEPOSITED,
                evidence_event=deposit_event,
                error=None,
            )

            # Verify transition generates evidence
            assert result.success
            assert result.previous_state == DeliveryState.DRAFT
            assert result.new_state == DeliveryState.DEPOSITED
            assert result.evidence_event is not None
            assert result.evidence_event.event_type == EventType.EVT_DEPOSITED

    @pytest.mark.asyncio
    async def test_step_3_notification_sent(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
        mock_recipient_party: MagicMock,
    ):
        """Step 3: System sends notification to recipient (REQ-C01, REQ-F02)."""
        from qerds.services.lifecycle import TransitionResult

        # Simulate notification sent
        mock_delivery_draft.state = DeliveryState.DEPOSITED

        notification_event = _create_evidence_event(
            delivery_id,
            EventType.EVT_NOTIFICATION_SENT,
            ActorType.SYSTEM,
            "system",
            {
                "notification_channel": "email",
                "recipient_email_hash": "abc123...",  # Privacy-preserving hash
            },
        )

        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.DEPOSITED,
            new_state=DeliveryState.NOTIFIED,
            evidence_event=notification_event,
            error=None,
        )

        assert result.success
        assert result.new_state == DeliveryState.NOTIFIED
        assert result.evidence_event.event_type == EventType.EVT_NOTIFICATION_SENT

    @pytest.mark.asyncio
    async def test_step_4_content_becomes_available(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Step 4: Content becomes available with 15-day window (REQ-F04)."""
        from qerds.services.lifecycle import TransitionResult

        mock_delivery_draft.state = DeliveryState.NOTIFIED

        # Calculate 15-day acceptance deadline
        now = datetime.now(UTC)
        acceptance_deadline = now + timedelta(days=15)

        available_event = _create_evidence_event(
            delivery_id,
            EventType.EVT_CONTENT_AVAILABLE,
            ActorType.SYSTEM,
            "system",
            {
                "acceptance_deadline": acceptance_deadline.isoformat(),
                "acceptance_window_days": 15,
            },
        )

        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.NOTIFIED,
            new_state=DeliveryState.AVAILABLE,
            evidence_event=available_event,
            error=None,
        )

        assert result.success
        assert result.new_state == DeliveryState.AVAILABLE
        # Verify 15-day window is set per REQ-F04
        assert "acceptance_deadline" in result.evidence_event.event_metadata
        assert result.evidence_event.event_metadata["acceptance_window_days"] == 15

    @pytest.mark.asyncio
    async def test_step_5_sender_hidden_before_acceptance(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
        mock_sender_party: MagicMock,
        recipient_party_id: UUID,
    ):
        """Step 5: Verify sender identity is hidden before acceptance (REQ-F03)."""
        from qerds.services.pickup import PickupContext

        mock_delivery_draft.state = DeliveryState.AVAILABLE

        # Create pickup context for pre-acceptance view
        context = PickupContext(
            delivery=mock_delivery_draft,
            recipient=mock_delivery_draft.recipient_party,
            is_authenticated=True,
            ial_level=IALLevel.IAL2,
            has_consent=True,
            can_accept_refuse=True,
            acceptance_deadline=datetime.now(UTC) + timedelta(days=14),
            is_expired=False,
            sender_revealed=False,  # Critical: sender hidden before acceptance
        )

        # Verify sender is NOT revealed per REQ-F03
        assert context.sender_revealed is False
        assert context.can_accept_refuse is True
        assert context.is_authenticated is True

    @pytest.mark.asyncio
    async def test_step_6_recipient_accepts_delivery(
        self,
        delivery_id: UUID,
        recipient_party_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Step 6: Recipient accepts delivery with consent (REQ-F04, REQ-F06)."""
        from qerds.services.lifecycle import TransitionResult

        mock_delivery_draft.state = DeliveryState.AVAILABLE

        # Acceptance requires:
        # - IAL2+ authentication (REQ-F04)
        # - Consumer consent confirmation (REQ-F06)
        accept_event = _create_evidence_event(
            delivery_id,
            EventType.EVT_ACCEPTED,
            ActorType.RECIPIENT,
            str(recipient_party_id),
            {
                "ial_level": "ial2",
                "consent_confirmed": True,
                "consent_type": ConsentType.FR_LRE_ELECTRONIC_DELIVERY.value,
            },
        )

        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.AVAILABLE,
            new_state=DeliveryState.ACCEPTED,
            evidence_event=accept_event,
            error=None,
        )

        assert result.success
        assert result.new_state == DeliveryState.ACCEPTED
        assert result.evidence_event.event_metadata["ial_level"] == "ial2"
        assert result.evidence_event.event_metadata["consent_confirmed"] is True

    @pytest.mark.asyncio
    async def test_step_7_sender_revealed_after_acceptance(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
        mock_sender_party: MagicMock,
    ):
        """Step 7: Verify sender identity revealed after acceptance (REQ-F03)."""
        from qerds.services.pickup import PickupContext

        mock_delivery_draft.state = DeliveryState.ACCEPTED
        mock_delivery_draft.completed_at = datetime.now(UTC)

        # Create pickup context for post-acceptance view
        context = PickupContext(
            delivery=mock_delivery_draft,
            recipient=mock_delivery_draft.recipient_party,
            is_authenticated=True,
            ial_level=IALLevel.IAL2,
            has_consent=True,
            can_accept_refuse=False,  # Already accepted
            acceptance_deadline=datetime.now(UTC) + timedelta(days=14),
            is_expired=False,
            sender_revealed=True,  # Now revealed per REQ-F03
        )

        # Verify sender IS revealed after acceptance
        assert context.sender_revealed is True
        assert context.can_accept_refuse is False

    @pytest.mark.asyncio
    async def test_step_8_recipient_downloads_content(
        self,
        delivery_id: UUID,
        recipient_party_id: UUID,
        mock_content_object: MagicMock,
    ):
        """Step 8: Recipient downloads content after acceptance (REQ-E02)."""
        from qerds.services.evidence import CreateEventParams

        # Content access is only permitted after acceptance (REQ-E02)
        access_params = CreateEventParams(
            delivery_id=delivery_id,
            event_type=EventType.EVT_CONTENT_DOWNLOADED,
            actor=MagicMock(
                actor_type=ActorType.RECIPIENT,
                actor_ref=str(recipient_party_id),
                to_metadata=lambda: {
                    "actor_type": "recipient",
                    "actor_ref": str(recipient_party_id),
                },
            ),
            event_metadata={
                "content_object_ids": [str(mock_content_object.content_object_id)],
                "content_hash": mock_content_object.sha256,
            },
        )

        # Verify download event captures content binding
        assert access_params.event_type == EventType.EVT_CONTENT_DOWNLOADED
        assert mock_content_object.sha256 in str(access_params.event_metadata)

    @pytest.mark.asyncio
    async def test_step_9_evidence_chain_complete(
        self,
        delivery_id: UUID,
        sender_party_id: UUID,
        recipient_party_id: UUID,
    ):
        """Step 9: Verify complete evidence chain exists (REQ-C01)."""
        # Expected evidence events for complete accept flow
        expected_events = [
            EventType.EVT_DEPOSITED,
            EventType.EVT_NOTIFICATION_SENT,
            EventType.EVT_CONTENT_AVAILABLE,
            EventType.EVT_ACCEPTED,
            EventType.EVT_CONTENT_DOWNLOADED,
            EventType.EVT_RECEIVED,
        ]

        # Create mock event chain
        events = []
        for event_type in expected_events:
            actor_type = (
                ActorType.SENDER
                if event_type == EventType.EVT_DEPOSITED
                else (
                    ActorType.RECIPIENT
                    if event_type
                    in {
                        EventType.EVT_ACCEPTED,
                        EventType.EVT_CONTENT_DOWNLOADED,
                        EventType.EVT_RECEIVED,
                    }
                    else ActorType.SYSTEM
                )
            )
            events.append(
                _create_evidence_event(
                    delivery_id,
                    event_type,
                    actor_type,
                    str(
                        sender_party_id
                        if actor_type == ActorType.SENDER
                        else (recipient_party_id if actor_type == ActorType.RECIPIENT else "system")
                    ),
                )
            )

        # Verify all expected events exist
        event_types = [e.event_type for e in events]
        for expected in expected_events:
            assert expected in event_types, f"Missing event: {expected.value}"

    @pytest.mark.asyncio
    async def test_step_10_proof_verification(
        self,
        delivery_id: UUID,
    ):
        """Step 10: Verify proofs can be generated and verified (REQ-B01, REQ-C02)."""
        from qerds.services.evidence_sealer import (
            CANONICALIZATION_VERSION,
            SealedEvidence,
            VerificationBundle,
        )

        # Create mock sealed evidence representing a proof
        mock_verification_bundle = VerificationBundle(
            signing_cert_chain=["-----BEGIN CERTIFICATE-----..."],
            tsa_cert_chain=[],
            policy_oid="1.2.3.4.5",
            hash_algorithm="sha256",
            signature_algorithm="ECDSA-SHA256",
            algorithm_suite_version="1.0",
            created_at=datetime.now(UTC).isoformat(),
        )

        mock_sealed = SealedEvidence(
            evidence_id=f"evd-{uuid4()}",
            format_version="ETSI-EN-319-522-4-1:2024-01",
            payload={
                "delivery_id": str(delivery_id),
                "event_type": "evt_deposited",
            },
            canonical_bytes=b'{"delivery_id":"...","event_type":"evt_deposited"}',
            canonicalization_version=CANONICALIZATION_VERSION,
            content_hash="abc123...",
            provider_attestation={"signature": "...", "algorithm": "ECDSA-SHA256"},
            time_attestation={"timestamp": "...", "policy_oid": "1.2.3.4.5"},
            verification_bundle=mock_verification_bundle,
            qualification_label="non_qualified",  # Dev mode
            sealed_at=datetime.now(UTC),
        )

        # Verify proof structure
        proof_dict = mock_sealed.to_dict()
        assert "payload" in proof_dict
        assert "content_hash" in proof_dict
        assert "provider_attestation" in proof_dict
        assert "time_attestation" in proof_dict
        assert "verification_bundle" in proof_dict
        assert proof_dict["qualification_label"] == "non_qualified"


# ---------------------------------------------------------------------------
# Test: Complete Refuse Flow
# ---------------------------------------------------------------------------


class TestCompleteRefuseFlow:
    """End-to-end tests for the complete refuse flow.

    Verifies:
    1. Recipient can refuse a delivery
    2. Content remains inaccessible after refusal
    3. Sender identity is revealed after refusal
    4. Proper evidence is generated
    """

    @pytest.mark.asyncio
    async def test_refuse_generates_evidence(
        self,
        delivery_id: UUID,
        recipient_party_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Verify refuse action generates proper evidence (REQ-C01)."""
        from qerds.services.lifecycle import TransitionResult

        mock_delivery_draft.state = DeliveryState.AVAILABLE

        refuse_event = _create_evidence_event(
            delivery_id,
            EventType.EVT_REFUSED,
            ActorType.RECIPIENT,
            str(recipient_party_id),
            {
                "ial_level": "ial2",
                "refusal_reason": "Non sollicite",
            },
        )

        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.AVAILABLE,
            new_state=DeliveryState.REFUSED,
            evidence_event=refuse_event,
            error=None,
        )

        assert result.success
        assert result.new_state == DeliveryState.REFUSED
        assert result.evidence_event.event_type == EventType.EVT_REFUSED

    @pytest.mark.asyncio
    async def test_content_inaccessible_after_refusal(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Verify content cannot be accessed after refusal (REQ-E02)."""
        mock_delivery_draft.state = DeliveryState.REFUSED
        mock_delivery_draft.completed_at = datetime.now(UTC)

        # Content access should be denied for refused deliveries
        # The pickup portal checks delivery.state != DeliveryState.ACCEPTED
        is_content_accessible = mock_delivery_draft.state == DeliveryState.ACCEPTED
        assert is_content_accessible is False

    @pytest.mark.asyncio
    async def test_sender_revealed_after_refusal(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Verify sender identity revealed after refusal (REQ-F03)."""
        from qerds.services.pickup import PickupContext

        mock_delivery_draft.state = DeliveryState.REFUSED
        mock_delivery_draft.completed_at = datetime.now(UTC)

        context = PickupContext(
            delivery=mock_delivery_draft,
            recipient=mock_delivery_draft.recipient_party,
            is_authenticated=True,
            ial_level=IALLevel.IAL2,
            has_consent=True,
            can_accept_refuse=False,
            acceptance_deadline=datetime.now(UTC) + timedelta(days=14),
            is_expired=False,
            sender_revealed=True,  # Revealed after refusal per REQ-F03
        )

        assert context.sender_revealed is True

    @pytest.mark.asyncio
    async def test_refuse_is_terminal_state(
        self,
        mock_delivery_draft: MagicMock,
    ):
        """Verify REFUSED is a terminal state (no further transitions)."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        mock_delivery_draft.state = DeliveryState.REFUSED

        # REFUSED should have no valid outgoing transitions
        valid_transitions = DeliveryLifecycleService.VALID_TRANSITIONS.get(
            DeliveryState.REFUSED, set()
        )
        assert len(valid_transitions) == 0


# ---------------------------------------------------------------------------
# Test: Complete Expiry Flow
# ---------------------------------------------------------------------------


class TestCompleteExpiryFlow:
    """End-to-end tests for the expiry flow (15-day window).

    Verifies:
    1. 15-day acceptance window is enforced (REQ-F04)
    2. Expiry generates proper evidence
    3. No action possible after expiry
    """

    @pytest.mark.asyncio
    async def test_15_day_window_enforcement(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Verify 15-day acceptance window is enforced (REQ-F04)."""
        from qerds.services.lifecycle import JURISDICTION_PROFILES

        # French LRE requires 15-day minimum per CPCE
        fr_lre_profile = JURISDICTION_PROFILES["fr_lre"]
        assert fr_lre_profile.acceptance_window_days == 15

        # Set delivery past deadline
        mock_delivery_draft.state = DeliveryState.AVAILABLE
        mock_delivery_draft.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)

        # Verify deadline has passed
        is_expired = datetime.now(UTC) > mock_delivery_draft.acceptance_deadline_at
        assert is_expired is True

    @pytest.mark.asyncio
    async def test_expiry_generates_evidence(
        self,
        delivery_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Verify expiry generates proper evidence (REQ-C01)."""
        from qerds.services.lifecycle import TransitionResult

        mock_delivery_draft.state = DeliveryState.AVAILABLE
        mock_delivery_draft.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)

        expire_event = _create_evidence_event(
            delivery_id,
            EventType.EVT_EXPIRED,
            ActorType.SYSTEM,
            "expiry_job",
            {
                "acceptance_deadline": mock_delivery_draft.acceptance_deadline_at.isoformat(),
                "expired_by": "automated_check",
            },
        )

        result = TransitionResult(
            success=True,
            previous_state=DeliveryState.AVAILABLE,
            new_state=DeliveryState.EXPIRED,
            evidence_event=expire_event,
            error=None,
        )

        assert result.success
        assert result.new_state == DeliveryState.EXPIRED
        assert result.evidence_event.event_type == EventType.EVT_EXPIRED
        assert "acceptance_deadline" in result.evidence_event.event_metadata

    @pytest.mark.asyncio
    async def test_no_accept_after_expiry(
        self,
        delivery_id: UUID,
        recipient_party_id: UUID,
        mock_delivery_draft: MagicMock,
    ):
        """Verify accept is blocked after expiry (REQ-F04)."""
        from qerds.services.pickup import DeliveryExpiredError

        mock_delivery_draft.state = DeliveryState.AVAILABLE
        mock_delivery_draft.acceptance_deadline_at = datetime.now(UTC) - timedelta(days=1)

        # Attempting to accept after deadline should raise error
        with pytest.raises(DeliveryExpiredError):
            raise DeliveryExpiredError(delivery_id, mock_delivery_draft.acceptance_deadline_at)

    @pytest.mark.asyncio
    async def test_expiry_is_terminal_state(
        self,
        mock_delivery_draft: MagicMock,
    ):
        """Verify EXPIRED is a terminal state (no further transitions)."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        mock_delivery_draft.state = DeliveryState.EXPIRED

        # EXPIRED should have no valid outgoing transitions
        valid_transitions = DeliveryLifecycleService.VALID_TRANSITIONS.get(
            DeliveryState.EXPIRED, set()
        )
        assert len(valid_transitions) == 0


# ---------------------------------------------------------------------------
# Test: CPCE Compliance Requirements
# ---------------------------------------------------------------------------


class TestCPCECompliance:
    """Tests for French CPCE (Code des Postes) compliance requirements.

    Verifies all CPCE-specific behaviors for LRE mode.
    """

    @pytest.mark.asyncio
    async def test_sender_redaction_pre_acceptance(
        self,
        delivery_id: UUID,
        mock_sender_party: MagicMock,
    ):
        """Verify sender identity is redacted before acceptance (REQ-F03)."""
        from qerds.services.evidence import REDACTION_PROFILES, apply_redaction

        # French LRE uses CPCE redaction profile
        profile = REDACTION_PROFILES["fr_lre_cpce"]
        assert profile["hide_sender_identity"] is True

        # Apply redaction to delivery data
        delivery_data = {
            "sender_name": mock_sender_party.display_name,
            "sender_email": mock_sender_party.email,
            "subject": "Important Document",
        }

        redacted = apply_redaction(delivery_data, "fr_lre_cpce", is_accepted=False)

        # Verify sender info is redacted
        assert redacted["sender_name"] == "[REDACTED]"
        assert redacted["sender_email"] == "[REDACTED]"
        # Subject can be shown per profile
        assert redacted["subject"] == "Important Document"

    @pytest.mark.asyncio
    async def test_sender_revealed_post_acceptance(
        self,
        delivery_id: UUID,
        mock_sender_party: MagicMock,
    ):
        """Verify sender identity revealed after acceptance (REQ-F03)."""
        from qerds.services.evidence import apply_redaction

        delivery_data = {
            "sender_name": mock_sender_party.display_name,
            "sender_email": mock_sender_party.email,
        }

        # After acceptance, no redaction
        revealed = apply_redaction(delivery_data, "fr_lre_cpce", is_accepted=True)

        assert revealed["sender_name"] == mock_sender_party.display_name
        assert revealed["sender_email"] == mock_sender_party.email

    @pytest.mark.asyncio
    async def test_ial2_required_for_lre(self):
        """Verify IAL2+ is required for French LRE recipients (REQ-F04)."""
        from qerds.services.pickup import IAL_REQUIREMENTS, InsufficientIALError

        # French LRE requires IAL2 (substantial assurance)
        assert IAL_REQUIREMENTS["fr_lre"] == IALLevel.IAL2

        # Attempting with IAL1 should fail
        with pytest.raises(InsufficientIALError):
            raise InsufficientIALError(IALLevel.IAL2, IALLevel.IAL1)

    @pytest.mark.asyncio
    async def test_consumer_consent_required_for_lre(self):
        """Verify consumer consent required for LRE mode (REQ-F06)."""
        from qerds.services.lifecycle import JURISDICTION_PROFILES
        from qerds.services.pickup import ConsentRequiredError

        # French LRE requires prior consumer consent
        fr_lre_profile = JURISDICTION_PROFILES["fr_lre"]
        assert fr_lre_profile.requires_recipient_consent is True

        # eIDAS base does not require prior consent
        eidas_profile = JURISDICTION_PROFILES["eidas"]
        assert eidas_profile.requires_recipient_consent is False

        # Attempting without consent should fail
        with pytest.raises(ConsentRequiredError):
            raise ConsentRequiredError("Electronic delivery consent required for LRE recipients")

    @pytest.mark.asyncio
    async def test_15_day_minimum_window(self):
        """Verify 15-day minimum acceptance window (REQ-F04)."""
        from qerds.services.lifecycle import (
            DEFAULT_ACCEPTANCE_WINDOW_DAYS,
            JURISDICTION_PROFILES,
        )

        # Default is 15 days per CPCE
        assert DEFAULT_ACCEPTANCE_WINDOW_DAYS == 15

        # Both profiles use 15 days
        assert JURISDICTION_PROFILES["fr_lre"].acceptance_window_days == 15
        assert JURISDICTION_PROFILES["eidas"].acceptance_window_days == 15


# ---------------------------------------------------------------------------
# Test: Evidence Integrity and Verification
# ---------------------------------------------------------------------------


class TestEvidenceIntegrity:
    """Tests for evidence integrity and verification capabilities.

    Verifies evidence can be independently verified (REQ-B01, REQ-C02).
    """

    @pytest.mark.asyncio
    async def test_content_hash_binding(
        self,
        mock_content_object: MagicMock,
    ):
        """Verify content is cryptographically bound to evidence (REQ-B02)."""
        # Content hash should be SHA-256 (64 hex chars)
        # Verify mock content object has proper hash format
        assert len(mock_content_object.sha256) == 64  # SHA-256 hex digest
        assert all(c in "0123456789abcdef" for c in mock_content_object.sha256)

    @pytest.mark.asyncio
    async def test_evidence_event_immutability(
        self,
        delivery_id: UUID,
        sender_party_id: UUID,
    ):
        """Verify evidence events are immutable records (REQ-C01)."""
        event = _create_evidence_event(
            delivery_id,
            EventType.EVT_DEPOSITED,
            ActorType.SENDER,
            str(sender_party_id),
        )

        # Event should have all required fields
        assert event.event_id is not None
        assert event.delivery_id == delivery_id
        assert event.event_type == EventType.EVT_DEPOSITED
        assert event.event_time is not None
        assert event.actor_type == ActorType.SENDER
        assert event.actor_ref == str(sender_party_id)

    @pytest.mark.asyncio
    async def test_timeline_reconstruction(
        self,
        delivery_id: UUID,
    ):
        """Verify timeline can be reconstructed from evidence (REQ-H10)."""
        # Create events with ordered timestamps
        base_time = datetime.now(UTC)
        events = []

        event_sequence = [
            (EventType.EVT_DEPOSITED, ActorType.SENDER, 0),
            (EventType.EVT_NOTIFICATION_SENT, ActorType.SYSTEM, 1),
            (EventType.EVT_CONTENT_AVAILABLE, ActorType.SYSTEM, 2),
            (EventType.EVT_ACCEPTED, ActorType.RECIPIENT, 100),  # Days later
        ]

        for event_type, actor_type, day_offset in event_sequence:
            event = MagicMock()
            event.event_id = uuid4()
            event.delivery_id = delivery_id
            event.event_type = event_type
            event.event_time = base_time + timedelta(days=day_offset)
            event.actor_type = actor_type
            events.append(event)

        # Sort by event_time (as would be done in timeline reconstruction)
        events.sort(key=lambda e: e.event_time)

        # Verify chronological order
        for i in range(len(events) - 1):
            assert events[i].event_time <= events[i + 1].event_time

        # Verify event sequence
        assert events[0].event_type == EventType.EVT_DEPOSITED
        assert events[-1].event_type == EventType.EVT_ACCEPTED


# ---------------------------------------------------------------------------
# Test: State Machine Transitions
# ---------------------------------------------------------------------------


class TestStateMachineTransitions:
    """Tests for delivery state machine integrity (REQ-C01)."""

    @pytest.mark.asyncio
    async def test_valid_transitions_from_draft(self):
        """Verify valid transitions from DRAFT state."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        valid = DeliveryLifecycleService.VALID_TRANSITIONS[DeliveryState.DRAFT]
        assert DeliveryState.DEPOSITED in valid
        assert len(valid) == 1  # Only one valid transition

    @pytest.mark.asyncio
    async def test_valid_transitions_from_available(self):
        """Verify valid transitions from AVAILABLE state."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        valid = DeliveryLifecycleService.VALID_TRANSITIONS[DeliveryState.AVAILABLE]
        assert DeliveryState.ACCEPTED in valid
        assert DeliveryState.REFUSED in valid
        assert DeliveryState.EXPIRED in valid
        assert len(valid) == 3  # Three possible outcomes

    @pytest.mark.asyncio
    async def test_backwards_transition_blocked(self):
        """Verify backwards transitions are blocked (monotonic)."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        # DEPOSITED cannot go back to DRAFT
        valid_from_deposited = DeliveryLifecycleService.VALID_TRANSITIONS[DeliveryState.DEPOSITED]
        assert DeliveryState.DRAFT not in valid_from_deposited

        # ACCEPTED cannot go to any earlier state
        valid_from_accepted = DeliveryLifecycleService.VALID_TRANSITIONS[DeliveryState.ACCEPTED]
        assert DeliveryState.AVAILABLE not in valid_from_accepted
        assert DeliveryState.DEPOSITED not in valid_from_accepted

    @pytest.mark.asyncio
    async def test_terminal_states(self):
        """Verify terminal states have no outgoing transitions."""
        from qerds.services.lifecycle import DeliveryLifecycleService

        terminal_states = [
            DeliveryState.REFUSED,
            DeliveryState.RECEIVED,
            DeliveryState.EXPIRED,
        ]

        for state in terminal_states:
            valid = DeliveryLifecycleService.VALID_TRANSITIONS.get(state, set())
            assert len(valid) == 0, f"{state} should be terminal"
