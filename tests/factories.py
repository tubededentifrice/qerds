"""Test data factories for QERDS.

This module provides factory functions for creating test data.
Use these to build consistent, valid test objects without duplicating
data structures across tests.
"""

from datetime import UTC, datetime
from uuid import uuid4


def create_delivery(
    sender_id: str | None = None,
    recipient_id: str | None = None,
    state: str = "draft",
    jurisdiction: str = "eidas",
    delivery_id: str | None = None,
) -> dict:
    """Create a test delivery dict.

    Args:
        sender_id: UUID of the sender party. Auto-generated if None.
        recipient_id: UUID of the recipient party. Auto-generated if None.
        state: Delivery state (draft, submitted, deposited, etc.)
        jurisdiction: Jurisdiction profile (eidas, franceconnect, etc.)
        delivery_id: UUID of the delivery. Auto-generated if None.

    Returns:
        Dict representing a delivery ready for tests.
    """
    return {
        "delivery_id": delivery_id or str(uuid4()),
        "state": state,
        "sender_party_id": sender_id or str(uuid4()),
        "recipient_party_id": recipient_id or str(uuid4()),
        "jurisdiction_profile": jurisdiction,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }


def create_evidence_event(
    delivery_id: str,
    event_type: str = "EVT_DEPOSITED",
    actor_type: str = "sender",
    actor_ref: str | None = None,
    event_id: str | None = None,
) -> dict:
    """Create a test evidence event dict.

    Args:
        delivery_id: UUID of the associated delivery.
        event_type: Type of event (EVT_DEPOSITED, EVT_SENT, EVT_DELIVERED, etc.)
        actor_type: Type of actor (sender, recipient, system)
        actor_ref: Reference to the actor. Auto-generated if None.
        event_id: UUID of the event. Auto-generated if None.

    Returns:
        Dict representing an evidence event ready for tests.
    """
    return {
        "event_id": event_id or str(uuid4()),
        "delivery_id": delivery_id,
        "event_type": event_type,
        "event_time": datetime.now(UTC),
        "actor_type": actor_type,
        "actor_ref": actor_ref or str(uuid4()),
    }


def create_content_blob(
    delivery_id: str,
    filename: str = "document.pdf",
    content_type: str = "application/pdf",
    size_bytes: int = 1024,
    blob_id: str | None = None,
) -> dict:
    """Create a test content blob dict.

    Args:
        delivery_id: UUID of the associated delivery.
        filename: Original filename.
        content_type: MIME type of the content.
        size_bytes: Size of the blob in bytes.
        blob_id: UUID of the blob. Auto-generated if None.

    Returns:
        Dict representing a content blob ready for tests.
    """
    return {
        "blob_id": blob_id or str(uuid4()),
        "delivery_id": delivery_id,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "storage_key": f"deliveries/{delivery_id}/blobs/{blob_id or str(uuid4())}",
        "created_at": datetime.now(UTC),
    }


def create_party(
    party_type: str = "natural_person",
    email: str | None = None,
    party_id: str | None = None,
    **kwargs,
) -> dict:
    """Create a test party dict.

    Args:
        party_type: Type of party (natural_person, legal_person)
        email: Email address. Auto-generated if None.
        party_id: UUID of the party. Auto-generated if None.
        **kwargs: Additional fields to include (given_name, family_name, etc.)

    Returns:
        Dict representing a party ready for tests.
    """
    pid = party_id or str(uuid4())
    base = {
        "party_id": pid,
        "party_type": party_type,
        "email": email or f"test-{pid[:8]}@example.com",
        "created_at": datetime.now(UTC),
    }

    if party_type == "natural_person":
        base.setdefault("given_name", kwargs.get("given_name", "Test"))
        base.setdefault("family_name", kwargs.get("family_name", "User"))
    elif party_type == "legal_person":
        base.setdefault("organization_name", kwargs.get("organization_name", "Test Corp"))

    base.update(kwargs)
    return base


def create_audit_log_entry(
    action: str,
    actor_id: str | None = None,
    resource_type: str = "delivery",
    resource_id: str | None = None,
    entry_id: str | None = None,
) -> dict:
    """Create a test audit log entry dict.

    Args:
        action: The action performed (create, update, access, etc.)
        actor_id: UUID of the actor who performed the action.
        resource_type: Type of resource affected.
        resource_id: UUID of the affected resource.
        entry_id: UUID of the entry. Auto-generated if None.

    Returns:
        Dict representing an audit log entry ready for tests.
    """
    return {
        "entry_id": entry_id or str(uuid4()),
        "timestamp": datetime.now(UTC),
        "action": action,
        "actor_id": actor_id or str(uuid4()),
        "resource_type": resource_type,
        "resource_id": resource_id or str(uuid4()),
        "ip_address": "127.0.0.1",
        "user_agent": "pytest/test-client",
    }
