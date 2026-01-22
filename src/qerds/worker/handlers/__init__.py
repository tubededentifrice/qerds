"""Job handlers for the QERDS worker service.

Each handler is responsible for processing a specific job type:
- notification: Send email notifications (initial/reminder)
- expiry: Check for delivery acceptance window expiry
- bounce: Process email bounce notifications
- checkpoint: Seal tamper-evident log checkpoints
- retention: Enforce data retention policies
"""

from qerds.worker.handlers.bounce import process_bounce_handler
from qerds.worker.handlers.checkpoint import seal_checkpoint_handler
from qerds.worker.handlers.expiry import check_expiry_handler
from qerds.worker.handlers.notification import send_notification_handler
from qerds.worker.handlers.retention import enforce_retention_handler

__all__ = [
    "check_expiry_handler",
    "enforce_retention_handler",
    "process_bounce_handler",
    "seal_checkpoint_handler",
    "send_notification_handler",
]
