"""QERDS service layer.

This package contains service implementations for external integrations
and business logic orchestration:
- ObjectStoreClient: S3-compatible storage integration
- AuditLogService: Tamper-evident audit logging (REQ-C05, REQ-D08, REQ-H03)
- JobQueueService: PostgreSQL-backed background job processing
- AuthorizationService: RBAC/ABAC authorization (REQ-D02, REQ-H06)
- PDFGenerator: PDF proof generation using WeasyPrint
"""
