"""QERDS service layer.

This package contains service implementations for external integrations
and business logic orchestration:
- ObjectStoreClient: S3-compatible storage integration
- AuditLogService: Tamper-evident audit logging (REQ-C05, REQ-D08, REQ-H03)
- JobQueueService: PostgreSQL-backed background job processing
- AuthorizationService: RBAC/ABAC authorization (REQ-D02, REQ-H06)
- DeliveryLifecycleService: Delivery state machine (REQ-C01, REQ-F04)
- EvidenceService: Evidence event generation (REQ-B01, REQ-C01, REQ-H10)
- EvidenceSealer: Evidence object sealing and timestamping (REQ-B02, REQ-C02, REQ-C03)
- PDFGenerator: PDF proof generation using WeasyPrint
- QualificationService: Qualification claim guardrails (REQ-A01, REQ-G01, REQ-G02)
- AlertingService: Security event alerting for incident detection (REQ-H04, REQ-D08)
"""

from qerds.services.alerting import (
    AlertChannel,
    AlertEventType,
    AlertingConfig,
    AlertingService,
    AlertPayload,
    AlertResult,
    AlertSeverity,
    create_alerting_config_from_env,
)
from qerds.services.qualification import (
    QualificationContext,
    QualificationError,
    QualificationService,
    create_qualification_service,
)

__all__ = [
    "AlertChannel",
    "AlertEventType",
    "AlertPayload",
    "AlertResult",
    "AlertSeverity",
    "AlertingConfig",
    "AlertingService",
    "QualificationContext",
    "QualificationError",
    "QualificationService",
    "create_alerting_config_from_env",
    "create_qualification_service",
]
