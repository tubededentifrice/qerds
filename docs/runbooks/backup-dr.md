# Backup and Disaster Recovery Runbook

**Covers**: REQ-D09 (Business continuity and DR), REQ-H08 (Business continuity evidence)

This runbook documents the backup, restore, and disaster recovery procedures for QERDS platform operators. All operations MUST be recorded in the platform's DR evidence system for audit compliance.

## Table of Contents

1. [Overview](#overview)
2. [Backup Scope](#backup-scope)
3. [RPO/RTO Targets](#rporto-targets)
4. [Scheduled Backups](#scheduled-backups)
5. [Restore Procedures](#restore-procedures)
6. [DR Drill Procedures](#dr-drill-procedures)
7. [Recording Evidence](#recording-evidence)

---

## Overview

The QERDS platform requires robust backup and disaster recovery capabilities to meet eIDAS and CPCE compliance requirements. This runbook provides step-by-step procedures for operators.

**Key Compliance Requirements**:
- Automated backups for all durable state (REQ-D09)
- Restore testing with verifiable results (REQ-D09)
- DR exercises with exported evidence (REQ-H08)
- All backup/restore/DR activities MUST be recorded in the platform

---

## Backup Scope

The following components MUST be included in backups:

### PostgreSQL Database

Contains all delivery records, evidence, parties, and audit logs.

```bash
# Connection details (from environment)
# POSTGRES_HOST, POSTGRES_PORT, POSTGRES_USER, POSTGRES_DB
```

**Backup command example**:
```bash
pg_dump -Fc -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER $POSTGRES_DB > qerds_backup_$(date +%Y%m%d_%H%M%S).dump
```

### Object Store (MinIO/S3)

Contains encrypted content objects, evidence bundles, and audit pack archives.

**Buckets to backup**:
- `qerds-content` - Encrypted delivery content
- `qerds-evidence` - Sealed evidence bundles
- `qerds-audit` - Audit pack archives
- `qerds-dr-evidence` - DR evidence artifacts

**Backup approach**: Use MinIO client or AWS CLI for S3-compatible sync:
```bash
mc mirror minio/qerds-content backup/qerds-content/
mc mirror minio/qerds-evidence backup/qerds-evidence/
mc mirror minio/qerds-audit backup/qerds-audit/
mc mirror minio/qerds-dr-evidence backup/qerds-dr-evidence/
```

### Audit Logs

Tamper-evident audit log chains. Stored in PostgreSQL but worth noting separately due to compliance importance.

### Configuration

- Environment configuration files
- Docker compose configuration
- Key storage (HSM-backed or file-based key material)
- Policy documents

---

## RPO/RTO Targets

| Metric | Target | Description |
|--------|--------|-------------|
| **RPO** (Recovery Point Objective) | 60 minutes | Maximum acceptable data loss |
| **RTO** (Recovery Time Objective) | 4 hours | Maximum acceptable downtime |

These targets should be validated during DR drills and recorded in the platform.

---

## Scheduled Backups

### Daily Backup Procedure

**Frequency**: Every 24 hours (recommended: 02:00 local time)

**Steps**:

1. **Pre-backup verification**:
   ```bash
   # Verify database connectivity
   psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT 1"

   # Verify object store connectivity
   mc ls minio/qerds-content
   ```

2. **Execute database backup**:
   ```bash
   BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
   pg_dump -Fc -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER $POSTGRES_DB \
     > /backup/postgresql/qerds_${BACKUP_DATE}.dump
   ```

3. **Execute object store backup**:
   ```bash
   for bucket in qerds-content qerds-evidence qerds-audit qerds-dr-evidence; do
     mc mirror minio/${bucket} /backup/s3/${bucket}/
   done
   ```

4. **Verify backup integrity**:
   ```bash
   # Check database dump is valid
   pg_restore --list /backup/postgresql/qerds_${BACKUP_DATE}.dump > /dev/null

   # Check backup size is reasonable (not empty)
   du -h /backup/postgresql/qerds_${BACKUP_DATE}.dump
   ```

5. **Record backup execution** (see [Recording Evidence](#recording-evidence))

### Weekly Full Backup

**Frequency**: Every 7 days (recommended: Sunday 02:00)

Same procedure as daily backup, but retained for longer period (30 days recommended).

### Backup Retention

| Backup Type | Retention |
|-------------|-----------|
| Daily | 7 days |
| Weekly | 30 days |
| Monthly | 1 year |

---

## Restore Procedures

### Database Restore

**When to use**: Database corruption, data loss, or DR scenario.

**Steps**:

1. **Stop application services**:
   ```bash
   docker compose stop qerds-api qerds-worker
   ```

2. **Restore database**:
   ```bash
   # Drop and recreate database (WARNING: destructive)
   psql -h $POSTGRES_HOST -U postgres -c "DROP DATABASE IF EXISTS qerds_restore"
   psql -h $POSTGRES_HOST -U postgres -c "CREATE DATABASE qerds_restore"

   # Restore from backup
   pg_restore -h $POSTGRES_HOST -U $POSTGRES_USER -d qerds_restore \
     /backup/postgresql/qerds_YYYYMMDD_HHMMSS.dump
   ```

3. **Verify restored data**:
   ```bash
   # Check record counts
   psql -h $POSTGRES_HOST -U $POSTGRES_USER -d qerds_restore \
     -c "SELECT COUNT(*) FROM deliveries"

   # Verify audit log chain integrity
   psql -h $POSTGRES_HOST -U $POSTGRES_USER -d qerds_restore \
     -c "SELECT COUNT(*) FROM audit_log_records"
   ```

4. **Swap databases** (if verified):
   ```bash
   psql -h $POSTGRES_HOST -U postgres << EOF
   ALTER DATABASE qerds RENAME TO qerds_old;
   ALTER DATABASE qerds_restore RENAME TO qerds;
   EOF
   ```

5. **Restart application services**:
   ```bash
   docker compose start qerds-api qerds-worker
   ```

6. **Record restore test** (see [Recording Evidence](#recording-evidence))

### Object Store Restore

**Steps**:

1. **Restore from backup**:
   ```bash
   for bucket in qerds-content qerds-evidence qerds-audit; do
     mc mirror /backup/s3/${bucket}/ minio/${bucket}/
   done
   ```

2. **Verify object counts match**:
   ```bash
   mc ls --recursive minio/qerds-content | wc -l
   mc ls --recursive /backup/s3/qerds-content | wc -l
   ```

---

## DR Drill Procedures

DR drills should be conducted **quarterly** at minimum.

### Pre-Drill Preparation

1. **Schedule the drill** with stakeholders
2. **Prepare test environment** (isolated from production)
3. **Document current production state** for comparison

### Drill Execution Checklist

**Scenario**: Complete infrastructure failure and recovery

1. [ ] **Start timer** - Record drill start time
2. [ ] **Simulate failure** - Shut down production services in test environment
3. [ ] **Restore database** - Follow database restore procedure
4. [ ] **Restore object store** - Follow object store restore procedure
5. [ ] **Start services** - Bring up application stack
6. [ ] **Validate functionality**:
   - [ ] Can create new delivery
   - [ ] Can retrieve existing delivery
   - [ ] Evidence verification passes
   - [ ] Audit log chain is intact
7. [ ] **Stop timer** - Record recovery completion time
8. [ ] **Calculate RTO** - Time from failure to operational
9. [ ] **Calculate RPO** - Check timestamp of last backup vs failure time
10. [ ] **Document findings** - Note any issues or improvements needed

### Post-Drill Documentation

After each drill, document:
- Date and time of drill
- Participants
- Scenario executed
- RTO measured (compare to target)
- RPO measured (compare to target)
- Issues encountered
- Action items for improvement

---

## Recording Evidence

**CRITICAL**: All backup, restore, and DR activities MUST be recorded in the platform for audit compliance.

### Recording a Backup Execution

Use the Admin API endpoint:

```bash
curl -X POST https://qerds.example.com/admin/dr-evidence/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "outcome": "success",
    "backup_scope": {
      "postgresql": true,
      "object_store": true,
      "audit_logs": true,
      "config": true
    },
    "duration_seconds": 120,
    "summary": "Scheduled daily backup completed successfully",
    "details": {
      "backup_id": "backup-20240115-001",
      "database_size_mb": 500,
      "object_count": 15000,
      "backup_location": "/backup/daily/20240115/"
    }
  }'
```

### Recording a Restore Test

```bash
curl -X POST https://qerds.example.com/admin/dr-evidence/restore-test \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "outcome": "success",
    "backup_scope": {
      "postgresql": true,
      "object_store": true,
      "audit_logs": true,
      "config": false
    },
    "duration_seconds": 1800,
    "summary": "Monthly restore test completed - all data verified",
    "details": {
      "source_backup": "backup-20240115-001",
      "records_restored": 50000,
      "verification_passed": true
    }
  }'
```

### Recording a DR Drill

```bash
curl -X POST https://qerds.example.com/admin/dr-evidence/dr-drill \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "outcome": "success",
    "duration_seconds": 14400,
    "rpo": {
      "target_minutes": 60,
      "measured_minutes": 45,
      "meets_target": true
    },
    "rto": {
      "target_minutes": 240,
      "measured_minutes": 180,
      "meets_target": true
    },
    "summary": "Q1 2024 DR drill completed - all targets met",
    "details": {
      "drill_id": "dr-drill-2024q1",
      "scenario": "Complete infrastructure failure",
      "participants": ["operator-1", "operator-2"],
      "issues_found": [],
      "action_items": []
    }
  }'
```

### Viewing DR Evidence

**List all evidence**:
```bash
curl https://qerds.example.com/admin/dr-evidence \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Get summary for a period**:
```bash
curl "https://qerds.example.com/admin/dr-evidence/summary?start_date=2024-01-01T00:00:00Z&end_date=2024-03-31T23:59:59Z" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Audit Pack Inclusion

DR evidence is automatically included in audit packs generated via the Admin API. When generating an audit pack for conformity assessment, the pack will include:

- All backup execution records in the date range
- All restore test records in the date range
- All DR drill records in the date range
- Summary statistics (success rates, RPO/RTO compliance)

---

## Troubleshooting

### Backup Fails

1. Check database connectivity
2. Check disk space on backup destination
3. Check PostgreSQL user permissions
4. Review PostgreSQL logs for errors

### Restore Fails

1. Verify backup file integrity with `pg_restore --list`
2. Check target database doesn't have active connections
3. Ensure sufficient disk space
4. Check PostgreSQL version compatibility

### DR Drill Issues

1. Document all issues encountered
2. Record the drill with "partial" outcome if targets not met
3. Create action items for improvement
4. Schedule follow-up drill after fixes

---

## References

- `specs/implementation/90-security-and-ops-controls.md` - Security and ops controls specification
- `specs/implementation/80-audit-and-conformity.md` - Audit and conformity requirements
- `src/qerds/services/dr_evidence.py` - DR evidence service implementation
- `src/qerds/api/routers/admin.py` - Admin API endpoints
