"""Consumer consent management service for LRE compliance.

Covers: REQ-F06 (Consumer consent)

This module implements consent management for CPCE LRE compliance:
- Track consent state per recipient (PENDING, GRANTED, WITHDRAWN)
- Block LRE delivery without valid consent
- Support consent withdrawal with audit trail
- Store and export consent evidence for compliance

Per CPCE requirements, consumer recipients must provide prior consent
before receiving electronic registered delivery (LRE). This consent:
- Must be recorded with audit trail
- Must be verifiable and exportable
- Can be withdrawn at any time (with audit trail)
- Blocks new LRE deliveries when not granted or withdrawn
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

from qerds.db.models.base import ConsentState, ConsentType

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.parties import RecipientConsent

logger = logging.getLogger(__name__)


class ConsentNotFoundError(Exception):
    """Raised when a consent record is not found."""

    def __init__(self, recipient_party_id: UUID, consent_type: ConsentType) -> None:
        self.recipient_party_id = recipient_party_id
        self.consent_type = consent_type
        super().__init__(
            f"Consent record not found for party {recipient_party_id} and type {consent_type.value}"
        )


class ConsentRequiredError(Exception):
    """Raised when attempting LRE delivery without valid consent."""

    def __init__(self, recipient_party_id: UUID, consent_type: ConsentType) -> None:
        self.recipient_party_id = recipient_party_id
        self.consent_type = consent_type
        super().__init__(
            f"Consent required for LRE delivery to party {recipient_party_id} "
            f"(type: {consent_type.value})"
        )


class ConsentAlreadyGrantedError(Exception):
    """Raised when attempting to grant consent that is already granted."""

    def __init__(self, consent_id: UUID) -> None:
        self.consent_id = consent_id
        super().__init__(f"Consent {consent_id} is already granted")


class ConsentWithdrawnError(Exception):
    """Raised when attempting operations on withdrawn consent."""

    def __init__(self, consent_id: UUID) -> None:
        self.consent_id = consent_id
        super().__init__(f"Consent {consent_id} has been withdrawn")


class InvalidConsentStateError(Exception):
    """Raised when consent is in an invalid state for the operation."""

    def __init__(self, consent_id: UUID, current_state: ConsentState, operation: str) -> None:
        self.consent_id = consent_id
        self.current_state = current_state
        self.operation = operation
        super().__init__(f"Cannot {operation} consent {consent_id} in state {current_state.value}")


@dataclass(frozen=True, slots=True)
class ConsentRecord:
    """Immutable representation of a consent record.

    Attributes:
        consent_id: Unique identifier for this consent.
        recipient_party_id: Party ID of the recipient.
        consent_type: Type of consent (jurisdiction-specific).
        state: Current consent state (PENDING, GRANTED, WITHDRAWN).
        consented_at: When consent was granted (None if never granted).
        consented_by: Party ID of who gave consent.
        withdrawn_at: When consent was withdrawn (None if not withdrawn).
        created_at: When this record was created.
        updated_at: When this record was last modified.
    """

    consent_id: UUID
    recipient_party_id: UUID
    consent_type: ConsentType
    state: ConsentState
    consented_at: datetime | None
    consented_by: UUID | None
    withdrawn_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ConsentEvidence:
    """Evidence bundle for consent actions (grant or withdrawal).

    This structure captures all information needed to prove consent
    was given or withdrawn, suitable for export and audit.

    Attributes:
        consent_id: Unique identifier for this consent.
        recipient_party_id: Party ID of the recipient.
        consent_type: Type of consent.
        action: The action taken (grant or withdraw).
        action_time: When the action occurred.
        actor_party_id: Who performed the action.
        ip_address: IP address of the actor.
        user_agent: User agent of the actor.
        consent_text_hash: Hash of the consent text shown to user.
        metadata: Additional jurisdiction-specific metadata.
        evidence_hash: Hash of the entire evidence bundle.
    """

    consent_id: UUID
    recipient_party_id: UUID
    consent_type: ConsentType
    action: str  # "grant" or "withdraw"
    action_time: datetime
    actor_party_id: UUID | None
    ip_address: str | None
    user_agent: str | None
    consent_text_hash: str | None
    metadata: dict[str, Any] | None
    evidence_hash: str


class ConsentService:
    """Service for managing recipient consent for LRE delivery.

    This service implements CPCE REQ-F06 requirements:
    - Track consent state per recipient
    - Validate consent before LRE delivery
    - Support consent grant and withdrawal with full audit trail
    - Generate and store consent evidence

    Example:
        service = ConsentService(session)

        # Check if recipient has valid consent
        has_consent = await service.has_valid_consent(
            recipient_party_id=uuid,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        )

        # Grant consent
        record = await service.grant_consent(
            recipient_party_id=uuid,
            consent_type=ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
            consented_by=uuid,
            ip_address="192.168.1.1",
        )

        # Verify before delivery
        await service.verify_consent_for_delivery(
            recipient_party_id=uuid,
            jurisdiction_profile="fr_lre",
        )
    """

    # Map jurisdiction profiles to required consent types
    JURISDICTION_CONSENT_TYPES: ClassVar[dict[str, ConsentType]] = {
        "fr_lre": ConsentType.FR_LRE_ELECTRONIC_DELIVERY,
        "eidas": ConsentType.EIDAS_ELECTRONIC_DELIVERY,
    }

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the consent service.

        Args:
            session: SQLAlchemy async session for database operations.
        """
        self._session = session

    async def get_consent(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
    ) -> RecipientConsent | None:
        """Get a consent record by recipient and type.

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent to look up.

        Returns:
            RecipientConsent or None if not found.
        """
        from sqlalchemy import select

        from qerds.db.models.parties import RecipientConsent

        query = select(RecipientConsent).where(
            RecipientConsent.recipient_party_id == recipient_party_id,
            RecipientConsent.consent_type == consent_type,
        )
        result = await self._session.execute(query)
        return result.scalar_one_or_none()

    async def get_or_create_consent(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
    ) -> RecipientConsent:
        """Get or create a consent record in PENDING state.

        Creates a new consent record in PENDING state if one doesn't exist.
        This establishes the consent record for tracking without granting consent.

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent.

        Returns:
            RecipientConsent (existing or newly created in PENDING state).
        """
        from qerds.db.models.parties import RecipientConsent

        existing = await self.get_consent(recipient_party_id, consent_type)
        if existing:
            return existing

        # Create new consent record in PENDING state
        now = datetime.now(UTC)
        consent = RecipientConsent(
            recipient_party_id=recipient_party_id,
            consent_type=consent_type,
            state=ConsentState.PENDING,
            created_at=now,
            updated_at=now,
        )
        self._session.add(consent)
        await self._session.flush()

        logger.info(
            "Created consent record in PENDING state",
            extra={
                "consent_id": str(consent.consent_id),
                "recipient_party_id": str(recipient_party_id),
                "consent_type": consent_type.value,
            },
        )

        return consent

    async def has_valid_consent(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
    ) -> bool:
        """Check if recipient has valid (GRANTED) consent.

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent to check.

        Returns:
            True if consent is GRANTED, False otherwise.
        """
        consent = await self.get_consent(recipient_party_id, consent_type)
        return consent is not None and consent.state == ConsentState.GRANTED

    async def get_consent_state(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
    ) -> ConsentState:
        """Get the current consent state for a recipient.

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent to check.

        Returns:
            Current ConsentState (PENDING if no record exists).
        """
        consent = await self.get_consent(recipient_party_id, consent_type)
        if consent is None:
            return ConsentState.PENDING
        return consent.state

    async def grant_consent(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
        *,
        consented_by: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        consent_text_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RecipientConsent:
        """Grant consent for a recipient.

        Transitions consent from PENDING to GRANTED state.
        Also allows re-granting consent that was previously WITHDRAWN.

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent to grant.
            consented_by: UUID of the party giving consent (if different from recipient).
            ip_address: IP address of the consenting user (for audit).
            user_agent: User agent of the consenting user (for audit).
            consent_text_hash: Hash of the consent text shown to user.
            metadata: Additional jurisdiction-specific metadata.

        Returns:
            Updated RecipientConsent record.

        Raises:
            ConsentAlreadyGrantedError: If consent is already GRANTED.
        """
        consent = await self.get_or_create_consent(recipient_party_id, consent_type)

        if consent.state == ConsentState.GRANTED:
            raise ConsentAlreadyGrantedError(consent.consent_id)

        now = datetime.now(UTC)

        # Update consent record
        consent.state = ConsentState.GRANTED
        consent.consented_at = now
        consent.consented_by = consented_by or recipient_party_id
        consent.consent_ip_address = ip_address
        consent.consent_user_agent = user_agent
        consent.updated_at = now

        # Build consent metadata
        consent_meta = dict(metadata) if metadata else {}
        if consent_text_hash:
            consent_meta["consent_text_hash"] = consent_text_hash
        consent.consent_metadata = consent_meta

        # Generate and store evidence
        evidence = self._build_consent_evidence(
            consent=consent,
            action="grant",
            action_time=now,
            ip_address=ip_address,
            user_agent=user_agent,
            consent_text_hash=consent_text_hash,
            metadata=metadata,
        )
        consent.consent_evidence_object_ref = await self._store_evidence(evidence)

        await self._session.flush()

        logger.info(
            "Consent granted",
            extra={
                "consent_id": str(consent.consent_id),
                "recipient_party_id": str(recipient_party_id),
                "consent_type": consent_type.value,
                "consented_by": str(consented_by) if consented_by else None,
            },
        )

        return consent

    async def withdraw_consent(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
        *,
        reason: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RecipientConsent:
        """Withdraw consent for a recipient.

        Transitions consent from GRANTED to WITHDRAWN state.
        Creates full audit trail of the withdrawal.

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent to withdraw.
            reason: Reason for withdrawal (for audit).
            ip_address: IP address of the user withdrawing (for audit).
            user_agent: User agent of the user withdrawing (for audit).
            metadata: Additional withdrawal metadata.

        Returns:
            Updated RecipientConsent record.

        Raises:
            ConsentNotFoundError: If no consent record exists.
            InvalidConsentStateError: If consent is not in GRANTED state.
        """
        consent = await self.get_consent(recipient_party_id, consent_type)

        if consent is None:
            raise ConsentNotFoundError(recipient_party_id, consent_type)

        if consent.state != ConsentState.GRANTED:
            raise InvalidConsentStateError(
                consent.consent_id,
                consent.state,
                "withdraw",
            )

        now = datetime.now(UTC)

        # Update consent record
        consent.state = ConsentState.WITHDRAWN
        consent.withdrawn_at = now
        consent.withdrawal_reason = reason
        consent.withdrawal_ip_address = ip_address
        consent.withdrawal_user_agent = user_agent
        consent.updated_at = now

        # Generate and store withdrawal evidence
        evidence = self._build_consent_evidence(
            consent=consent,
            action="withdraw",
            action_time=now,
            ip_address=ip_address,
            user_agent=user_agent,
            consent_text_hash=None,
            metadata=metadata,
        )
        consent.withdrawal_evidence_object_ref = await self._store_evidence(evidence)

        await self._session.flush()

        logger.info(
            "Consent withdrawn",
            extra={
                "consent_id": str(consent.consent_id),
                "recipient_party_id": str(recipient_party_id),
                "consent_type": consent_type.value,
                "reason": reason,
            },
        )

        return consent

    async def verify_consent_for_delivery(
        self,
        recipient_party_id: UUID,
        jurisdiction_profile: str,
    ) -> bool:
        """Verify recipient has valid consent for LRE delivery.

        This method should be called before sending an LRE to ensure
        CPCE compliance. It raises an exception if consent is not valid.

        Args:
            recipient_party_id: UUID of the recipient party.
            jurisdiction_profile: Jurisdiction profile (e.g., "fr_lre", "eidas").

        Returns:
            True if consent is valid.

        Raises:
            ConsentRequiredError: If consent is not GRANTED.
            ValueError: If jurisdiction_profile is not recognized.
        """
        consent_type = self.JURISDICTION_CONSENT_TYPES.get(jurisdiction_profile)
        if consent_type is None:
            raise ValueError(
                f"Unknown jurisdiction profile: {jurisdiction_profile}. "
                f"Valid profiles: {list(self.JURISDICTION_CONSENT_TYPES.keys())}"
            )

        has_consent = await self.has_valid_consent(recipient_party_id, consent_type)

        if not has_consent:
            logger.warning(
                "LRE delivery blocked: consent not granted",
                extra={
                    "recipient_party_id": str(recipient_party_id),
                    "jurisdiction_profile": jurisdiction_profile,
                    "consent_type": consent_type.value,
                },
            )
            raise ConsentRequiredError(recipient_party_id, consent_type)

        return True

    async def get_consent_record(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
    ) -> ConsentRecord:
        """Get a consent record as an immutable dataclass.

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent.

        Returns:
            ConsentRecord with current state.

        Raises:
            ConsentNotFoundError: If no consent record exists.
        """
        consent = await self.get_consent(recipient_party_id, consent_type)

        if consent is None:
            raise ConsentNotFoundError(recipient_party_id, consent_type)

        return ConsentRecord(
            consent_id=consent.consent_id,
            recipient_party_id=consent.recipient_party_id,
            consent_type=consent.consent_type,
            state=consent.state,
            consented_at=consent.consented_at,
            consented_by=consent.consented_by,
            withdrawn_at=consent.withdrawn_at,
            created_at=consent.created_at,
            updated_at=consent.updated_at,
        )

    async def list_consents_for_party(
        self,
        recipient_party_id: UUID,
    ) -> list[ConsentRecord]:
        """List all consent records for a recipient.

        Args:
            recipient_party_id: UUID of the recipient party.

        Returns:
            List of ConsentRecord objects.
        """
        from sqlalchemy import select

        from qerds.db.models.parties import RecipientConsent

        query = select(RecipientConsent).where(
            RecipientConsent.recipient_party_id == recipient_party_id,
        )
        result = await self._session.execute(query)
        consents = result.scalars().all()

        return [
            ConsentRecord(
                consent_id=c.consent_id,
                recipient_party_id=c.recipient_party_id,
                consent_type=c.consent_type,
                state=c.state,
                consented_at=c.consented_at,
                consented_by=c.consented_by,
                withdrawn_at=c.withdrawn_at,
                created_at=c.created_at,
                updated_at=c.updated_at,
            )
            for c in consents
        ]

    async def export_consent_evidence(
        self,
        recipient_party_id: UUID,
        consent_type: ConsentType,
    ) -> dict[str, Any]:
        """Export consent evidence for compliance/audit.

        Returns a complete evidence bundle including:
        - Current consent state
        - Grant evidence (if applicable)
        - Withdrawal evidence (if applicable)
        - Full audit trail

        Args:
            recipient_party_id: UUID of the recipient party.
            consent_type: Type of consent.

        Returns:
            Dict containing full consent evidence bundle.

        Raises:
            ConsentNotFoundError: If no consent record exists.
        """
        consent = await self.get_consent(recipient_party_id, consent_type)

        if consent is None:
            raise ConsentNotFoundError(recipient_party_id, consent_type)

        evidence_bundle = {
            "consent_id": str(consent.consent_id),
            "recipient_party_id": str(consent.recipient_party_id),
            "consent_type": consent.consent_type.value,
            "state": consent.state.value,
            "created_at": consent.created_at.isoformat(),
            "updated_at": consent.updated_at.isoformat(),
            "grant_evidence": None,
            "withdrawal_evidence": None,
        }

        # Include grant evidence if consent was ever granted
        if consent.consented_at:
            evidence_bundle["grant_evidence"] = {
                "consented_at": consent.consented_at.isoformat(),
                "consented_by": str(consent.consented_by) if consent.consented_by else None,
                "ip_address": consent.consent_ip_address,
                "user_agent": consent.consent_user_agent,
                "evidence_ref": consent.consent_evidence_object_ref,
                "metadata": consent.consent_metadata,
            }

        # Include withdrawal evidence if consent was withdrawn
        if consent.withdrawn_at:
            evidence_bundle["withdrawal_evidence"] = {
                "withdrawn_at": consent.withdrawn_at.isoformat(),
                "reason": consent.withdrawal_reason,
                "ip_address": consent.withdrawal_ip_address,
                "user_agent": consent.withdrawal_user_agent,
                "evidence_ref": consent.withdrawal_evidence_object_ref,
            }

        return evidence_bundle

    def _build_consent_evidence(
        self,
        consent: RecipientConsent,
        action: str,
        action_time: datetime,
        ip_address: str | None,
        user_agent: str | None,
        consent_text_hash: str | None,
        metadata: dict[str, Any] | None,
    ) -> ConsentEvidence:
        """Build a consent evidence object.

        Args:
            consent: The consent record.
            action: The action ("grant" or "withdraw").
            action_time: When the action occurred.
            ip_address: IP address of the actor.
            user_agent: User agent of the actor.
            consent_text_hash: Hash of consent text (for grants).
            metadata: Additional metadata.

        Returns:
            ConsentEvidence object with computed hash.
        """
        # Build canonical representation for hashing
        canonical = {
            "consent_id": str(consent.consent_id),
            "recipient_party_id": str(consent.recipient_party_id),
            "consent_type": consent.consent_type.value,
            "action": action,
            "action_time": action_time.isoformat(),
            "actor_party_id": str(consent.consented_by) if consent.consented_by else None,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "consent_text_hash": consent_text_hash,
            "metadata": metadata,
        }

        # Compute evidence hash
        canonical_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        evidence_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        return ConsentEvidence(
            consent_id=consent.consent_id,
            recipient_party_id=consent.recipient_party_id,
            consent_type=consent.consent_type,
            action=action,
            action_time=action_time,
            actor_party_id=consent.consented_by,
            ip_address=ip_address,
            user_agent=user_agent,
            consent_text_hash=consent_text_hash,
            metadata=metadata,
            evidence_hash=evidence_hash,
        )

    async def _store_evidence(self, evidence: ConsentEvidence) -> str:
        """Store consent evidence and return a reference.

        In production, this would upload to S3/MinIO object storage.
        For now, we use an inline reference format.

        Args:
            evidence: The consent evidence to store.

        Returns:
            Reference string for retrieving the evidence.
        """
        # Build evidence payload
        payload = {
            "consent_id": str(evidence.consent_id),
            "recipient_party_id": str(evidence.recipient_party_id),
            "consent_type": evidence.consent_type.value,
            "action": evidence.action,
            "action_time": evidence.action_time.isoformat(),
            "actor_party_id": str(evidence.actor_party_id) if evidence.actor_party_id else None,
            "ip_address": evidence.ip_address,
            "user_agent": evidence.user_agent,
            "consent_text_hash": evidence.consent_text_hash,
            "metadata": evidence.metadata,
            "evidence_hash": evidence.evidence_hash,
        }

        # For development, embed as inline reference
        # Production would upload to S3: f"s3://consent-evidence/{consent_id}/{action}.json"
        payload_json = json.dumps(payload, sort_keys=True, default=str)
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()[:16]

        return f"inline:consent:{evidence.consent_id}:{evidence.action}:{payload_hash}"
