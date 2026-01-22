"""QERDS Worker service.

PostgreSQL-backed background job runner for:
- Outbound notifications (email) with retries
- Scheduled transitions (e.g., delivery expiry)
- Periodic sealing of tamper-evident log checkpoints
- Retention enforcement (archive/delete with audit trails)
- Backup/DR exercise helpers
"""
