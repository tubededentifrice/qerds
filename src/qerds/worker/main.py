"""QERDS Worker service entry point."""

import logging
import signal
import sys
from typing import NoReturn

logger = logging.getLogger(__name__)

# Graceful shutdown flag
_shutdown_requested = False


def _handle_shutdown(signum: int, _frame: object) -> None:
    """Handle shutdown signals gracefully."""
    global _shutdown_requested
    logger.info("Shutdown signal received (signal=%d)", signum)
    _shutdown_requested = True


def run() -> NoReturn:
    """Run the worker process.

    This is a placeholder for the PostgreSQL-backed job runner.
    The actual implementation will use SKIP LOCKED for job claiming.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    logger.info("QERDS Worker starting...")
    logger.info("Worker is a stub - implementation pending")

    # Placeholder: actual implementation will poll job table
    while not _shutdown_requested:
        signal.pause()

    logger.info("QERDS Worker shutting down")
    sys.exit(0)


if __name__ == "__main__":
    run()
