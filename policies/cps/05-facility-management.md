# CPS Section 5: Facility, Management, and Operational Controls

**Document Status**: SKELETON
**Classification**: Internal (summary may be published)
**Covers**: REQ-D01, REQ-D02

## 5.1 Physical Security Controls

### 5.1.1 Site Location and Construction

[TODO: Define site requirements]

Provider facilities MUST:

- [TODO: Physical security requirements]

### 5.1.2 Physical Access

[TODO: Define physical access controls]

Physical access controls include:

- Multi-factor entry systems
- Access logging and monitoring
- Visitor escort requirements
- [TODO: Additional controls]

### 5.1.3 Power and Air Conditioning

[TODO: Define power/cooling requirements]

### 5.1.4 Water Exposure

[TODO: Define water protection measures]

### 5.1.5 Fire Prevention and Protection

[TODO: Define fire protection]

### 5.1.6 Media Storage

[TODO: Define media storage requirements]

### 5.1.7 Waste Disposal

[TODO: Define secure disposal procedures]

### 5.1.8 Off-site Backup

[TODO: Define off-site backup requirements]

**Implementation**: See `policies/continuity-policy.md` for backup requirements.

## 5.2 Procedural Controls

### 5.2.1 Trusted Roles

[TODO: Define trusted roles]

| Role | Responsibilities | Requirements |
|------|-----------------|--------------|
| Security Officer | [TODO] | [TODO] |
| System Administrator | [TODO] | [TODO] |
| Operator | [TODO] | [TODO] |
| Auditor | [TODO] | [TODO] |

### 5.2.2 Number of Persons Required per Task

[TODO: Define multi-person control requirements]

Sensitive operations requiring multi-person control:

- Key generation ceremonies
- Key destruction
- [TODO: Other operations]

### 5.2.3 Identification and Authentication per Role

[TODO: Define authentication requirements per role]

**Covers**: REQ-D02

All privileged access requires:

- Strong authentication (MFA)
- Unique identifiers
- Attributable audit trails

### 5.2.4 Roles Requiring Separation of Duties

[TODO: Define separation of duties]

**Implementation**: See `specs/implementation/20-identities-and-roles.md` for role definitions.

## 5.3 Personnel Controls

### 5.3.1 Qualifications, Experience, and Clearance

[TODO: Define personnel requirements]

### 5.3.2 Background Checks

[TODO: Define background check requirements]

### 5.3.3 Training Requirements

[TODO: Define training requirements]

- Security awareness training
- Role-specific training
- Incident response training

### 5.3.4 Retraining Frequency

[TODO: Define retraining frequency]

### 5.3.5 Job Rotation

[TODO: Define rotation policy if applicable]

### 5.3.6 Sanctions for Unauthorized Actions

[TODO: Define sanctions policy]

### 5.3.7 Contractor Controls

[TODO: Define contractor requirements]

### 5.3.8 Documentation Supplied to Personnel

[TODO: Define documentation requirements]

## 5.4 Audit Logging Procedures

**Covers**: REQ-D08

### 5.4.1 Types of Events Recorded

[TODO: Reference implementation spec]

**Implementation**: See `specs/implementation/50-audit-logging-and-immutability.md` for event types.

### 5.4.2 Log Processing Frequency

[TODO: Define log review frequency]

### 5.4.3 Log Retention Period

[TODO: Define retention period]

### 5.4.4 Log Protection

Logs MUST be tamper-evident and protected.

**Implementation**: See `specs/implementation/50-audit-logging-and-immutability.md`.

### 5.4.5 Log Backup Procedures

[TODO: Define log backup]

### 5.4.6 Audit Log Collection System

[TODO: Define collection system]

### 5.4.7 Vulnerability Assessments

**Implementation**: See `policies/security-policy.md` for vulnerability management.

## 5.5 Records Archival

### 5.5.1 Types of Records Archived

[TODO: Define archived records]

### 5.5.2 Retention Period

[TODO: Define retention periods]

**Implementation**: See `specs/implementation/70-storage-and-retention.md`.

### 5.5.3 Archive Protection

[TODO: Define archive protection]

### 5.5.4 Archive Backup Procedures

[TODO: Define archive backup]

### 5.5.5 Requirements for Time-stamping of Records

Evidence records include qualified timestamps per REQ-C03.

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md`.

### 5.5.6 Archive Collection System

[TODO: Define collection system]

### 5.5.7 Archive Verification

[TODO: Define verification procedures]

## 5.6 Key Changeover

[TODO: Define key transition procedures]

**Implementation**: See `policies/key-management-policy.md` for key rotation.

## 5.7 Compromise and Disaster Recovery

### 5.7.1 Incident and Compromise Handling

**Implementation**: See `policies/incident-policy.md`.

### 5.7.2 Recovery Procedures

**Implementation**: See `policies/continuity-policy.md`.

### 5.7.3 Service Termination

[TODO: Define termination procedures]

## Cross-References

- **Security Policy**: `policies/security-policy.md`
- **Incident Policy**: `policies/incident-policy.md`
- **Continuity Policy**: `policies/continuity-policy.md`
- **Key Management Policy**: `policies/key-management-policy.md`
- **Audit Logging**: `specs/implementation/50-audit-logging-and-immutability.md`
- **Identities and Roles**: `specs/implementation/20-identities-and-roles.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
