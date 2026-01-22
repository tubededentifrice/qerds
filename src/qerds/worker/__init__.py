"""QERDS Worker service.

Covers: REQ-F04 (scheduled expiry), REQ-C05 (audit log sealing), REQ-H02 (retention enforcement)

PostgreSQL-backed background job runner for:
- Outbound notifications (email) with retries
- Scheduled transitions (e.g., delivery expiry)
- Periodic sealing of tamper-evident log checkpoints
- Retention enforcement (archive/delete with audit trails)
- Email bounce processing

Usage:
    # Run as module
    python -m qerds.worker

    # Or in Docker
    docker compose exec qerds-worker python -m qerds.worker
"""

from qerds.worker.main import Worker, WorkerConfig, run

__all__ = ["Worker", "WorkerConfig", "run"]
