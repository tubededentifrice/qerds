"""Checkpoint job handler for sealing tamper-evident log checkpoints.

Covers: REQ-C05 (audit log immutability)

This handler periodically seals audit log checkpoints by:
- Verifying chain integrity
- Creating a timestamped checkpoint record
- Optionally requesting an external timestamp (RFC3161)
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from qerds.db.models.base import AuditStream
from qerds.services.audit_log import AuditEventType, AuditLogService

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from qerds.db.models.jobs import Job

logger = logging.getLogger(__name__)

# All audit streams to checkpoint
AUDIT_STREAMS = [
    AuditStream.EVIDENCE,
    AuditStream.SECURITY,
    AuditStream.OPS,
]


async def seal_checkpoint_handler(
    session: AsyncSession,
    job: Job,
) -> dict[str, Any] | None:
    """Handle log_checkpoint jobs for audit log sealing.

    This handler:
    1. Retrieves the latest record from each audit stream
    2. Verifies chain integrity (optional)
    3. Creates a checkpoint record with hashes
    4. Logs the checkpoint for compliance

    Expected job payload:
        streams: (optional) List of stream names to checkpoint (default: all)
        verify_chain: (optional) Whether to verify chain integrity (default: True)

    Args:
        session: Database session for the transaction.
        job: The job being processed.

    Returns:
        Result dict with checkpoint details.
    """
    payload = job.payload_json or {}

    # Determine which streams to checkpoint
    streams_to_check = payload.get("streams")
    streams = [AuditStream(s) for s in streams_to_check] if streams_to_check else AUDIT_STREAMS

    verify_chain = payload.get("verify_chain", True)
    now = datetime.now(UTC)

    audit_service = AuditLogService(session)
    checkpoint_data: dict[str, Any] = {
        "checkpoint_time": now.isoformat(),
        "streams": {},
    }

    all_valid = True
    errors: list[str] = []

    for stream in streams:
        stream_result = await _checkpoint_stream(
            audit_service=audit_service,
            stream=stream,
            verify=verify_chain,
        )

        checkpoint_data["streams"][stream.value] = stream_result

        if not stream_result.get("valid", True):
            all_valid = False
            errors.extend(stream_result.get("errors", []))

    # Compute checkpoint hash (digest of all stream hashes)
    checkpoint_hash = _compute_checkpoint_hash(checkpoint_data)
    checkpoint_data["checkpoint_hash"] = checkpoint_hash

    # Log the checkpoint itself to the OPS stream
    await audit_service.append(
        stream=AuditStream.OPS,
        event_type=AuditEventType.CONFIG_SNAPSHOT,  # Using config_snapshot for checkpoints
        actor_type="system",
        actor_id="worker:checkpoint",
        payload={
            "checkpoint_type": "audit_log_seal",
            "checkpoint_hash": checkpoint_hash,
            "streams_checked": [s.value for s in streams],
            "all_valid": all_valid,
            "errors": errors if errors else None,
        },
        summary={
            "checkpoint_hash": checkpoint_hash[:16],
            "all_valid": all_valid,
            "streams_count": len(streams),
        },
    )

    if not all_valid:
        logger.error(
            "Audit log checkpoint found integrity errors: errors=%s",
            errors,
        )
    else:
        logger.info(
            "Audit log checkpoint completed: checkpoint_hash=%s, streams=%d",
            checkpoint_hash[:16],
            len(streams),
        )

    return {
        "checkpoint_hash": checkpoint_hash,
        "checkpoint_time": now.isoformat(),
        "streams_checked": [s.value for s in streams],
        "all_valid": all_valid,
        "errors": errors if errors else None,
    }


async def _checkpoint_stream(
    audit_service: AuditLogService,
    stream: AuditStream,
    verify: bool,
) -> dict[str, Any]:
    """Checkpoint a single audit stream.

    Args:
        audit_service: The audit log service.
        stream: The audit stream to checkpoint.
        verify: Whether to verify chain integrity.

    Returns:
        Dict with stream checkpoint details.
    """
    result: dict[str, Any] = {
        "stream": stream.value,
        "valid": True,
    }

    # Get the latest record in the stream
    latest = await audit_service.get_latest_record(stream)

    if latest is None:
        result["seq_no"] = 0
        result["record_hash"] = None
        result["empty"] = True
        return result

    result["seq_no"] = latest.seq_no
    result["record_hash"] = latest.record_hash
    result["last_record_id"] = str(latest.record_id)
    result["last_event_type"] = latest.event_type

    # Optionally verify chain integrity
    if verify:
        verification = await audit_service.verify_chain(stream)
        result["valid"] = verification.valid
        result["checked_records"] = verification.checked_records
        result["errors"] = verification.errors if verification.errors else None

        if not verification.valid:
            logger.error(
                "Chain integrity violation in stream %s: errors=%s",
                stream.value,
                verification.errors,
            )

    return result


def _compute_checkpoint_hash(checkpoint_data: dict[str, Any]) -> str:
    """Compute SHA-256 hash of checkpoint data.

    Args:
        checkpoint_data: The checkpoint data to hash.

    Returns:
        Hex-encoded SHA-256 hash.
    """
    # Extract relevant fields for hashing
    hash_input = {
        "checkpoint_time": checkpoint_data["checkpoint_time"],
        "streams": {},
    }

    for stream_name, stream_data in checkpoint_data["streams"].items():
        hash_input["streams"][stream_name] = {
            "seq_no": stream_data.get("seq_no"),
            "record_hash": stream_data.get("record_hash"),
        }

    # Deterministic JSON serialization
    canonical = json.dumps(hash_input, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
