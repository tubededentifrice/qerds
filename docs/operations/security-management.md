# Security Management Operations Guide

**Covers**: REQ-D01 (Security management), REQ-D02 (Least privilege)

This guide explains how to operate an Information Security Management System (ISMS) with the QERDS platform.

---

## Table of Contents

1. [Information Security Management System (ISMS)](#information-security-management-system-isms)
2. [Security Roles and Responsibilities](#security-roles-and-responsibilities)
3. [Risk Assessment](#risk-assessment)
4. [Security Controls Provided by Platform](#security-controls-provided-by-platform)
5. [Operational Security Procedures](#operational-security-procedures)
6. [Monitoring and Review](#monitoring-and-review)
7. [Documentation Requirements](#documentation-requirements)

---

## Information Security Management System (ISMS)

### What is ISMS

An Information Security Management System (ISMS) is a systematic approach to managing sensitive information to ensure its confidentiality, integrity, and availability. For QERDS providers, an ISMS is mandatory for qualification as a trust service provider.

The ISMS encompasses:
- **Policies**: High-level statements of intent and direction
- **Procedures**: Documented processes for security operations
- **Controls**: Technical and organizational safeguards
- **Records**: Evidence of compliance activities

### ETSI EN 319 401 Alignment

QERDS providers must operate in accordance with ETSI EN 319 401 (General policy requirements for trust service providers). Key requirements include:

| ETSI EN 319 401 Section | Requirement | Platform Support |
|-------------------------|-------------|------------------|
| 6.2 | Risk assessment | Risk register templates |
| 6.3 | Human resources security | Role-based access control |
| 6.4 | Asset management | Audit logging of all assets |
| 6.5 | Access control | RBAC/ABAC implementation |
| 6.6 | Cryptographic controls | Envelope encryption, key management |
| 6.7 | Physical and environmental | Operator responsibility |
| 6.8 | Operations security | Audit trails, change management |
| 6.9 | Communications security | TLS, network isolation |
| 6.10 | Incident management | Security event logging |
| 6.11 | Business continuity | DR evidence recording |
| 6.12 | Compliance | Audit pack export |

### Role of the Platform vs Organizational Processes

The QERDS platform provides **technical enablers** for security controls. However, the **provider organization** must:

- Establish and maintain security policies
- Appoint security personnel
- Conduct risk assessments
- Perform periodic reviews
- Respond to incidents
- Maintain compliance documentation

**Platform provides:**
- Access control enforcement (`src/qerds/services/authz.py`)
- Tamper-evident audit logging (`src/qerds/services/audit_log.py`)
- Content encryption (`src/qerds/services/encryption.py`)
- Security event recording (`src/qerds/services/security_events.py`)
- Audit pack export for conformity assessment

**Organization provides:**
- Security policy documents
- Risk assessment methodology
- Personnel vetting and training
- Incident response team
- Management commitment and oversight

---

## Security Roles and Responsibilities

The platform enforces role-based access control with the following role classes (defined in `src/qerds/services/authz.py`):

### Security Officer Responsibilities

**Role class**: `security_officer`

The Security Officer is responsible for:
- Overseeing the ISMS implementation
- Approving security-sensitive changes (dual-control)
- Reviewing security events and audit logs
- Coordinating incident response
- Conducting security awareness activities
- Reporting to management

**Platform permissions**:
- `KEY_MANAGEMENT` - Cryptographic key lifecycle
- `CONFIG_CHANGE` - Security configuration changes
- `SECURITY_SETTINGS` - Security policy settings
- `VIEW_AUDIT_LOGS` / `EXPORT_AUDIT_LOGS` - Audit log access
- `VIEW_USERS` / `VIEW_CLIENTS` - Identity review

**Note**: Key management and config changes require dual-control approval (two authorized persons).

### Administrator Responsibilities

**Role class**: `admin`

Administrators are responsible for:
- Managing user accounts and roles
- Configuring platform settings
- Monitoring system health
- Performing routine maintenance
- Escalating security concerns

**Platform permissions**:
- `ADMIN_ACCESS` - Administrative interface access
- `VIEW_USERS` / `MANAGE_USERS` - User administration
- `VIEW_CLIENTS` / `MANAGE_CLIENTS` - API client administration
- `VIEW_ROLES` / `MANAGE_ROLES` - Role management
- `VIEW_DELIVERIES` / `VIEW_EVIDENCE` - Operational oversight
- `VIEW_AUDIT_LOGS` - Audit log review

### Operator Responsibilities

Operators (including Support and Registration Officers) are responsible for:
- Day-to-day service operations
- Handling user inquiries
- Verifying identities (Registration Officers)
- Resolving delivery issues

**Support role permissions** (`support`):
- `VIEW_SUPPORT_CASES` / `MANAGE_SUPPORT_CASES`
- `VIEW_DELIVERIES`
- `VIEW_USERS`

**Registration Officer permissions** (`registration_officer`):
- `VERIFY_IDENTITY`
- `MANAGE_IDENTITY_PROOFS`
- `VIEW_USERS`

### Segregation of Duties

The platform enforces separation of duties to prevent conflicts of interest and reduce fraud risk:

| Role Combination | Status | Reason |
|------------------|--------|--------|
| Admin + Auditor | Prohibited | Prevents self-audit |
| Security Officer + Admin | Prohibited | Enforces dual-control |
| Registration Officer + Sender/Recipient | Prohibited | Prevents identity fraud |

**Dual-control operations** (require two authorized persons):
- Key generation and rotation
- Security configuration changes
- Audit log export
- Any operation with `KEY_MANAGEMENT`, `CONFIG_CHANGE`, or `SECURITY_SETTINGS` permission

The dual-control workflow:
1. First authorized person creates a request
2. Second authorized person (different identity) approves or rejects
3. Operation executes only after approval
4. All steps are logged in the security audit stream

---

## Risk Assessment

### Asset Inventory

QERDS providers must maintain an inventory of information assets. Categories include:

| Asset Category | Examples | Criticality |
|----------------|----------|-------------|
| Evidence data | Delivery proofs, timestamps, seals | Critical |
| Cryptographic keys | KEK, signing keys, TLS certificates | Critical |
| User data | Identities, credentials, contact info | High |
| Audit logs | Security events, evidence chain | High |
| Configuration | Security settings, access policies | High |
| Application code | Platform source, dependencies | Medium |
| Infrastructure | Servers, networks, storage | Medium |

### Threat Identification

Common threats to QERDS providers:

| Threat | Impact | Controls |
|--------|--------|----------|
| Unauthorized access | Confidentiality breach | RBAC, MFA, audit logging |
| Data tampering | Integrity loss, legal invalidity | Hash chains, qualified seals |
| Key compromise | Complete trust failure | HSM (qualified), dual-control |
| Insider threat | All CIA properties | Separation of duties, audit |
| Service disruption | Availability loss | DR procedures, monitoring |
| Evidence destruction | Legal liability | Immutable logs, backups |

### Risk Evaluation

Use a risk matrix to prioritize risks:

```
Impact
  ^
  |  Medium   High     Critical
  |  Low      Medium   High
  |  Minimal  Low      Medium
  +-------------------------> Likelihood
```

Document risks with:
- Risk ID and description
- Asset(s) affected
- Threat and vulnerability
- Likelihood and impact scores
- Existing controls
- Residual risk rating
- Treatment decision

### Risk Treatment

Options for each identified risk:
- **Accept**: Risk is within tolerance
- **Mitigate**: Implement additional controls
- **Transfer**: Insurance or contractual allocation
- **Avoid**: Eliminate the activity causing the risk

Document treatment decisions and track implementation of mitigation measures.

---

## Security Controls Provided by Platform

### Access Control

**Implementation**: `src/qerds/services/authz.py`

The platform implements:
- **RBAC (Role-Based Access Control)**: Permissions granted via role assignments
- **ABAC (Attribute-Based Access Control)**: Fine-grained access based on resource ownership, organization membership
- **Dual-control**: Sensitive operations require two authorized persons

Key features:
- Permission checks on all protected operations
- Resource-level authorization (sender/recipient can only access their deliveries)
- Organization-scoped access
- Inactive account enforcement

### Audit Logging

**Implementation**: `src/qerds/services/audit_log.py`

All security-relevant events are logged with:
- **Tamper-evidence**: SHA-256 hash chain prevents undetected modification
- **Immutability**: Append-only design, no update/delete operations
- **Completeness**: Actor, action, resource, outcome, timestamp for every event

Three audit streams:
- `EVIDENCE`: Delivery lifecycle events
- `SECURITY`: Authentication, authorization, admin actions
- `OPS`: Configuration changes, deployments, backups

Chain verification detects:
- Record deletion (sequence gaps)
- Record modification (hash mismatch)
- Record reordering (chain break)

### Encryption

**Implementation**: `src/qerds/services/encryption.py`

Content protection uses envelope encryption:
- **DEK (Data Encryption Key)**: AES-256-GCM, per-content object
- **KEK (Key Encryption Key)**: Protects DEKs, managed separately
- **Integrity**: SHA-256 content hash verified on decryption

Key management:
- KEK stored encrypted at rest (password-derived key, PBKDF2)
- Secure file permissions (0600)
- Qualification label distinguishes dev/qualified modes

### Security Events

**Implementation**: `src/qerds/services/security_events.py`

High-level API for security event logging:
- Authentication events (success, failure, logout, MFA)
- Authorization decisions (granted, denied)
- Admin actions (user management, role changes)
- Key operations (generate, rotate, revoke)
- Configuration changes
- Sensitive data access

All events logged to the SECURITY audit stream with full tamper-evidence.

---

## Operational Security Procedures

### Change Management

All changes to the platform must follow a controlled process:

1. **Request**: Document the change, justification, and risk assessment
2. **Review**: Security Officer reviews security-impacting changes
3. **Test**: Verify in non-production environment
4. **Approve**: Obtain required approvals (dual-control for security changes)
5. **Implement**: Deploy with rollback capability
6. **Verify**: Confirm change was successful
7. **Close**: Update documentation and change register

The platform records deployment markers in the OPS audit stream (see `AuditEventType.DEPLOYMENT_MARKER`).

### Incident Response

**Detection**: The platform logs security events that may indicate incidents:
- Multiple authentication failures
- Authorization denials
- Unusual admin actions
- Configuration changes outside maintenance windows

**Response procedure**:
1. **Identify**: Confirm the incident is real
2. **Contain**: Limit damage (disable accounts, isolate systems)
3. **Eradicate**: Remove the threat
4. **Recover**: Restore normal operations
5. **Learn**: Post-incident review and improvements

Use `SecurityEventLogger.export_events()` to extract timeline for investigation.

### Backup and Recovery

See: [Backup and Disaster Recovery Runbook](../runbooks/backup-dr.md)

Key points:
- Daily database and object store backups
- Monthly restore tests with verification
- Quarterly DR drills with evidence recording
- All backup/restore/DR activities logged via Admin API

### Access Reviews

Periodic access reviews required per REQ-H06:

**Quarterly review checklist**:
- [ ] Export current user list and role assignments
- [ ] Verify each user still requires their access
- [ ] Remove access for terminated employees
- [ ] Review privileged role assignments (admin, security_officer)
- [ ] Check for dormant accounts (no login for 90 days)
- [ ] Verify dual-control role separation is maintained
- [ ] Document review in access review register

Use Admin API to export access review artifacts.

---

## Monitoring and Review

### Security Event Monitoring

**Real-time monitoring** (recommended):
- Forward security stream to SIEM
- Alert on authentication failures (threshold: 5 in 10 minutes)
- Alert on authorization denials for admin operations
- Alert on key operations outside maintenance windows

**Daily review**:
- Review security event summary
- Investigate any anomalies
- Verify no chain integrity errors

**Platform query example**:
```python
# Get recent security events
events = await security_logger.get_events(
    event_type=SecurityEventType.AUTH_FAILURE,
    limit=100,
)
```

### Log Review Procedures

**Weekly log review**:
1. Export security events for the week
2. Review authentication patterns
3. Review authorization denials
4. Review admin actions
5. Verify no unexpected key operations
6. Document findings in log review register

**Monthly review**:
1. Verify audit log chain integrity for all streams
2. Review access patterns for privileged accounts
3. Check for configuration drift
4. Update risk register if new threats identified

### Periodic Control Reviews

**Quarterly**:
- Vulnerability scan (REQ-D05)
- Access review (REQ-H06)
- Backup restore test
- Network security validation (`make check-network-prod`)

**Annually**:
- Penetration test (REQ-D06)
- Full DR exercise (REQ-H08)
- Security policy review
- ISMS management review

### Management Reviews

Management should review ISMS effectiveness periodically (at least annually):

**Inputs**:
- Audit and assessment results
- Incident statistics
- Control effectiveness metrics
- Risk treatment status
- Customer feedback
- Changes affecting the ISMS

**Outputs**:
- Improvement decisions
- Resource allocation
- Policy updates
- Objectives for the coming period

---

## Documentation Requirements

### Policy Documents

Required policies for QERDS qualification (per ETSI EN 319 401/521):

| Policy | Description | Review Frequency |
|--------|-------------|------------------|
| Information Security Policy | High-level ISMS commitment | Annual |
| Access Control Policy | Authentication, authorization rules | Annual |
| Cryptographic Policy | Key management, algorithm choices | Annual |
| Incident Management Policy | Detection, response, reporting | Annual |
| Business Continuity Policy | DR objectives, procedures | Annual |
| Evidence Management Policy | Retention, integrity, access | Annual |
| Change Management Policy | Change control process | Annual |

See: [docs/policies/](../policies/) for policy templates

### Procedures

Operational procedures (update as processes change):

| Procedure | Location |
|-----------|----------|
| Backup and Recovery | [docs/runbooks/backup-dr.md](../runbooks/backup-dr.md) |
| Network Security | [docs/deployment/network-security.md](../deployment/network-security.md) |
| Deployment Checklist | [docs/deployment/operator-checklist.md](../deployment/operator-checklist.md) |
| Access Reviews | This document (above) |
| Incident Response | This document (above) |

### Records

Records to maintain for audit evidence:

| Record Type | Retention | Source |
|-------------|-----------|--------|
| Security events | 7 years | SECURITY audit stream |
| Evidence events | 10 years minimum | EVIDENCE audit stream |
| Operations events | 3 years | OPS audit stream |
| Access review reports | 3 years | Admin API export |
| Incident reports | 7 years | Manual documentation |
| Risk assessments | Current + 1 version | Manual documentation |
| Policy versions | Current + historical | Document management |
| DR drill evidence | 3 years | DR evidence API |

### Evidence Retention

Per REQ-H02 and CPCE requirements:

| Evidence Type | Minimum Retention |
|---------------|-------------------|
| Proof of receipt | 1 year (CPCE minimum) |
| Delivery evidence bundles | 10 years (recommended) |
| Audit logs | Per applicable requirements |
| Cryptographic verification data | Same as associated evidence |

The platform stores evidence with retention metadata and supports retention-controlled export via the Admin API.

---

## Related Documentation

- [Backup and Disaster Recovery Runbook](../runbooks/backup-dr.md)
- [Network Security](../deployment/network-security.md)
- [Operator Deployment Checklist](../deployment/operator-checklist.md)
- `specs/requirements.md` - Full requirements specification
- `src/qerds/services/authz.py` - Access control implementation
- `src/qerds/services/audit_log.py` - Audit logging implementation
- `src/qerds/services/encryption.py` - Encryption service implementation
- `src/qerds/services/security_events.py` - Security event logging implementation

---

## Qualification Reminder

This documentation supports security management for QERDS operation. However:

**Do not claim "qualified" status unless:**
- Provider is actually qualified and supervised for QERDS
- Service is listed in relevant EU trusted lists
- All normative requirements are demonstrably met
- Conformity assessment has been passed

See `specs/requirements.md` for the full requirements list and REQ-G01/REQ-G02 for compliance guardrails.
