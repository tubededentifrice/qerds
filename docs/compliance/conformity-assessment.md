# Conformity Assessment Preparation Guide

**Covers**: REQ-A02 (Conformity assessment), REQ-H01 (Audit evidence exportability)

This guide explains how to prepare for and pass conformity assessments required for QERDS and LRE qualification. It is intended for platform operators seeking to achieve or maintain qualified trust service status.

## Table of Contents

1. [What is Conformity Assessment?](#what-is-conformity-assessment)
2. [Evidence Required for Assessment](#evidence-required-for-assessment)
3. [Pre-Assessment Checklist](#pre-assessment-checklist)
4. [During Assessment](#during-assessment)
5. [Post-Assessment](#post-assessment)
6. [Platform Features for Assessment](#platform-features-for-assessment)

---

## What is Conformity Assessment?

Conformity assessment is the process by which a provider demonstrates compliance with the requirements for qualified trust services under eIDAS and applicable harmonised standards.

### Purpose and Scope

The conformity assessment verifies that:

- The service meets all technical requirements for QERDS (eIDAS Article 44)
- The provider's operational policies align with ETSI EN 319 401/319 521
- Security controls are implemented and effective
- Evidence lifecycle management is robust and tamper-evident
- Business continuity and incident response capabilities are adequate

For French LRE services, the assessment also covers CPCE-specific requirements (R. 53-1 to R. 53-4).

### Assessment Body Selection

Conformity assessments must be performed by an accredited Conformity Assessment Body (CAB). When selecting a CAB:

- Verify accreditation under **ETSI EN 319 403** (assessment of conformity assessment bodies)
- Ensure the CAB has experience with ERDS/QERDS assessments
- Confirm the CAB's scope covers all relevant standards (EN 319 521, EN 319 522)
- For French LRE, verify the CAB understands CPCE requirements

The CAB must be independent and have no conflicts of interest with the provider.

### Assessment Frequency

| Assessment Type | Frequency | Trigger |
|-----------------|-----------|---------|
| Initial qualification | Once | Before claiming qualified status |
| Periodic surveillance | Every 24 months | Maintaining qualification |
| Re-assessment | As needed | Significant changes to service |
| Ad-hoc review | As needed | Security incidents, supervisory body request |

Significant changes that may trigger re-assessment include:

- Major version upgrades to the platform
- Changes to cryptographic mechanisms or key management
- Changes to the evidence lifecycle or storage architecture
- Changes to the provider's operational policies

---

## Evidence Required for Assessment

Assessors will request various evidence artifacts. The platform provides tools to generate and export these materials.

### Technical Documentation

Assessors will review:

| Document | Purpose | Platform Support |
|----------|---------|------------------|
| System architecture | Understand component relationships | Generate from conformity package |
| Security architecture | Verify defense-in-depth | Configuration snapshots in audit pack |
| Cryptographic specifications | Verify algorithm compliance | Included in audit pack |
| Evidence format specifications | Verify ETSI EN 319 522 compliance | Sample evidence bundles |
| API documentation | Understand interfaces | OpenAPI specification |

### Policy Documents

The provider must maintain and provide:

| Policy | ETSI Reference | Notes |
|--------|---------------|-------|
| Trust Service Policy | EN 319 401 Section 6.1 | What the service does and guarantees |
| Certification Practice Statement | EN 319 521 Section 6.3 | How the service implements policy |
| Security Policy | EN 319 401 Section 7.1 | Information security controls |
| Key Management Policy | EN 319 521 Section 6.4.3 | Key lifecycle and ceremonies |
| Incident Response Plan | EN 319 401 Section 7.9 | Incident handling procedures |
| Business Continuity Plan | EN 319 401 Section 7.10 | DR and continuity measures |
| Data Protection Policy | GDPR, EN 319 401 | Privacy and data handling |

The platform stores policy document references and versions. Configuration snapshots reference the active policy version at any point in time (REQ-A03).

### Operational Evidence

Assessors will request evidence of operational practices:

| Evidence Type | Retention | Source |
|---------------|-----------|--------|
| Backup execution logs | 1 year minimum | DR evidence API |
| Restore test results | 1 year minimum | DR evidence API |
| DR drill reports | 3 years minimum | DR evidence API |
| Vulnerability scan reports | 1 year minimum | Vulnerability evidence API |
| Penetration test reports | 2 years minimum | Vulnerability evidence API |
| Access review records | 2 years minimum | Access review API |
| Key ceremony logs | Lifetime of service | Key inventory API |
| Incident reports | 5 years minimum | Security events API |

### Using the Audit Pack Feature

The platform's audit pack generator (`POST /admin/audit-packs`) consolidates most required evidence into a single, sealed archive. Each audit pack includes:

- Evidence samples with verification bundles
- Audit log integrity proofs for the period
- Configuration snapshots
- Cryptographic parameters
- Key inventory metadata
- DR evidence summaries
- Vulnerability management summaries
- Policy document references
- Release/SBOM metadata

Audit packs are timestamped and sealed to prove they have not been modified after generation.

---

## Pre-Assessment Checklist

Complete this checklist before the assessment date.

### Platform Configuration Review

- [ ] **Qualification mode**: Verify `QERDS_CLAIM_STATE=qualified` is set correctly
- [ ] **Cryptographic configuration**: All algorithms comply with ENISA recommendations
- [ ] **Key storage**: HSM or equivalent secure storage is operational
- [ ] **Timestamp source**: Qualified timestamp provider is configured and tested
- [ ] **Evidence retention**: Retention periods meet requirements (1 year for LRE proofs)
- [ ] **Network security**: Run `make check-network-prod` with no critical issues
- [ ] **TLS configuration**: Certificates valid, modern TLS only
- [ ] **Access controls**: RBAC configured, least privilege enforced

### Policy Document Completeness

- [ ] **Trust Service Policy**: Current version published and accessible
- [ ] **CPS**: Aligned with platform configuration
- [ ] **Security Policy**: Covers all EN 319 401 Section 7 requirements
- [ ] **Key Management Policy**: Documents key generation, storage, rotation, revocation
- [ ] **Incident Response Plan**: Tested within last 12 months
- [ ] **Business Continuity Plan**: DR drill conducted within last 12 months
- [ ] **Policy versioning**: All policies have version history and change log

### Evidence Collection

Generate the following before the assessment:

```bash
# Generate a conformity package for the assessment
curl -X POST https://qerds.example.com/admin/conformity-packages \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "assessment_type": "initial_qualification",
    "reason": "Preparation for [CAB Name] conformity assessment",
    "include_evidence_samples": true,
    "include_key_ceremonies": true
  }'

# Generate an audit pack covering the pre-assessment period
curl -X POST https://qerds.example.com/admin/audit-packs \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "start_date": "2024-01-01T00:00:00Z",
    "end_date": "2024-12-31T23:59:59Z",
    "reason": "Conformity assessment by [CAB Name]",
    "include_evidence": true,
    "include_security_logs": true,
    "include_ops_logs": true,
    "include_config_snapshots": true
  }'

# Export the traceability matrix
curl https://qerds.example.com/admin/traceability-matrix \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -o traceability-matrix.json
```

### Test Environment Preparation

If assessors will perform technical testing:

- [ ] **Isolated environment**: Test environment mirrors production configuration
- [ ] **Test accounts**: Create assessor accounts with appropriate access
- [ ] **Test data**: Prepare representative test deliveries
- [ ] **Monitoring**: Ensure assessor activity can be observed
- [ ] **Documentation**: Provide environment access instructions

---

## During Assessment

### What Assessors Will Examine

Assessors typically follow the structure of ETSI EN 319 401/319 521. Expect examination of:

**Governance and Organisation**
- Provider legal status and liability
- Roles and responsibilities
- Subcontractor management
- Risk management processes

**Human Resources**
- Staff competence and training
- Background checks
- Role separation
- Security awareness

**Asset Management**
- Hardware and software inventory
- Media handling
- Asset disposal

**Access Control**
- Authentication mechanisms
- Authorisation policies
- Privileged access management
- Access review evidence

**Cryptographic Controls**
- Algorithm selection and configuration
- Key management lifecycle
- Secure key storage
- Cryptographic module certification

**Physical Security**
- Facility access controls
- Environmental controls
- Equipment security

**Operations Security**
- Change management
- Capacity management
- Malware protection
- Backup and recovery
- Logging and monitoring

**Network Security**
- Network segmentation
- Firewall configuration
- Intrusion detection

**Incident Management**
- Incident response procedures
- Incident reporting
- Incident evidence

**Business Continuity**
- BCP documentation
- DR testing evidence
- Recovery procedures

**Compliance**
- Regulatory compliance
- Audit evidence
- Self-assessment results

### Technical Demonstrations

Assessors may request live demonstrations of:

| Capability | What to Demonstrate |
|------------|---------------------|
| Delivery lifecycle | Send a test delivery, show evidence generation |
| Evidence verification | Verify a sealed evidence bundle |
| Recipient notification | Show notification flow and access controls |
| Refusal/acceptance | Demonstrate recipient actions |
| Audit trail | Show tamper-evident log entries |
| Key ceremony | Walk through key generation process |
| Backup/restore | Show backup execution and restore verification |
| Incident response | Walk through incident handling workflow |

### Document Reviews

Have the following readily accessible:

- Current versions of all policy documents
- Change logs for policies and system
- Training records for key personnel
- Third-party audit reports (penetration tests, vulnerability scans)
- Incident reports from the assessment period
- Access review documentation
- Key ceremony records

### Staff Interviews

Assessors will interview personnel to verify:

- Understanding of their roles and responsibilities
- Knowledge of security policies and procedures
- Incident response awareness
- Evidence handling procedures

Key personnel likely to be interviewed:

- Service manager / operations lead
- Security officer
- System administrators
- Key custodians

---

## Post-Assessment

### Addressing Findings

Assessors may identify:

| Finding Type | Definition | Typical Response |
|--------------|------------|------------------|
| Major non-conformity | Fundamental failure to meet requirements | Remediation required before qualification |
| Minor non-conformity | Partial or inconsistent implementation | Remediation required within agreed timeframe |
| Observation | Improvement opportunity | Address at provider discretion |

For each finding:

1. **Acknowledge** the finding in writing
2. **Analyse** the root cause
3. **Plan** remediation with timeline
4. **Implement** the fix
5. **Verify** the fix is effective
6. **Document** the remediation evidence
7. **Submit** evidence to the CAB

### Remediation Timeline

| Finding Severity | Typical Deadline |
|-----------------|------------------|
| Major non-conformity | Before qualification granted |
| Minor non-conformity | 30-90 days |
| Observation | Next surveillance audit |

The CAB will specify exact deadlines. Track remediation using the platform's issue tracking.

### Re-Assessment Triggers

A new assessment may be required if:

- Major changes are made to the service architecture
- A security incident occurs that affects trust service operation
- The supervisory body requests re-assessment
- The 24-month surveillance period expires
- The provider requests scope extension

Document all significant changes and consult with your CAB to determine if re-assessment is needed.

---

## Platform Features for Assessment

The QERDS platform provides several features to support conformity assessment.

### Audit Pack Generation

**Endpoint**: `POST /admin/audit-packs`

Generates a comprehensive, sealed archive containing evidence and logs for a date range.

```bash
curl -X POST https://qerds.example.com/admin/audit-packs \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "start_date": "2024-01-01T00:00:00Z",
    "end_date": "2024-12-31T23:59:59Z",
    "reason": "Annual conformity assessment",
    "include_evidence": true,
    "include_security_logs": true,
    "include_ops_logs": true,
    "include_config_snapshots": true
  }'
```

The response includes:
- `pack_id`: Unique identifier for the pack
- `storage_ref`: Location in object storage
- `pack_hash`: SHA-256 hash of the sealed pack
- `verification`: Integrity verification results

### Traceability Matrix

**Endpoint**: `GET /admin/traceability-matrix`

Exports the requirement-to-implementation traceability matrix (REQ-A04).

```bash
curl https://qerds.example.com/admin/traceability-matrix \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

The response includes:
- Mapping of each requirement ID to implementation modules
- Test coverage for each requirement
- Evidence artifacts for each requirement
- Implementation status (implemented, partial, not_implemented)

### Conformity Packages

**Endpoint**: `POST /admin/conformity-packages`

Generates a package specifically structured for conformity assessment.

```bash
curl -X POST https://qerds.example.com/admin/conformity-packages \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "assessment_type": "initial_qualification",
    "reason": "QERDS initial qualification assessment",
    "include_evidence_samples": true,
    "include_key_ceremonies": true
  }'
```

Assessment types:
- `initial_qualification`: First-time qualification assessment
- `surveillance`: Periodic surveillance audit
- `re_assessment`: Re-assessment after significant changes
- `scope_extension`: Adding new capabilities to qualification scope

The package includes:
- Traceability matrix
- Policy document references
- Evidence samples
- Configuration snapshots
- Key ceremony records
- Release and SBOM metadata

---

## References

### Standards

- **ETSI EN 319 401**: General policy requirements for trust service providers
- **ETSI EN 319 403**: Assessment of conformity assessment bodies
- **ETSI EN 319 521**: Policy and security requirements for ERDS
- **ETSI EN 319 522**: ERDS evidence and interoperability

### Regulations

- **eIDAS (Regulation (EU) 910/2014)**: Electronic identification and trust services
- **Implementing Regulation (EU) 2025/1944**: Rules for ERDS under eIDAS
- **CPCE (France)**: Postal and electronic communications code (R. 53-1 to R. 53-4)

### Related Documentation

- [Backup and Disaster Recovery Runbook](../runbooks/backup-dr.md)
- [Operator Deployment Checklist](../deployment/operator-checklist.md)
- [Requirements Specification](../../specs/requirements.md)
- [Audit and Conformity Specification](../../specs/implementation/80-audit-and-conformity.md)
