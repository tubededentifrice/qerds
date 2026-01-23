# Evidence Management Policy

**Document ID**: POL-EVI-001
**Version**: 0.1 (TEMPLATE)
**Classification**: Internal
**Covers**: REQ-C01 (Complete event coverage), REQ-C02 (Evidence authenticity), REQ-C05 (Immutability), REQ-H02 (Evidence retention controls), REQ-A03 (Policies and CPS)

> **NOTICE**: This is a placeholder policy document. The provider MUST complete all TODO sections with operational details before the service can be considered qualified under eIDAS/ETSI EN 319 401/521.

---

## 1. Scope and Purpose

### 1.1 Scope

This policy applies to all evidence generated and managed by the QERDS service, including:

- Proof of submission/deposit
- Proof of notification
- Proof of availability
- Proof of receipt/acceptance
- Proof of refusal
- Proof of non-claim/negligence
- Audit logs and supporting evidence

### 1.2 Purpose

This Evidence Management Policy establishes the controls for creating, protecting, and retaining evidence in the QERDS service. It ensures:

- Complete coverage of all lifecycle events (REQ-C01)
- Evidence authenticity and integrity (REQ-C02)
- Tamper-evident protection (REQ-C05)
- Compliant retention and retrieval (REQ-H02)
- Support for the legal presumption under eIDAS Article 44

### 1.3 Normative References

- Regulation (EU) No 910/2014 (eIDAS), Article 44
- Commission Implementing Regulation (EU) 2025/1944
- ETSI EN 319 521 (Policy and security requirements for ERDS)
- ETSI EN 319 522 (ERDS evidence and interoperability)
- CPCE Articles R.53-1 to R.53-4 (France LRE requirements)

---

## 2. Roles and Responsibilities

> **TODO**: The provider MUST define the specific individuals or roles responsible for evidence management.

### 2.1 Evidence Management Roles

| Role | Responsibilities | Assigned To |
|------|------------------|-------------|
| Evidence Manager | Policy ownership, retention oversight | TODO |
| Service Manager | Day-to-day evidence operations | TODO |
| Security Officer | Evidence security controls | TODO |
| Compliance Officer | Regulatory compliance verification | TODO |

### 2.2 Operational Responsibilities

| Responsibility | Role |
|----------------|------|
| Evidence generation configuration | Service Manager |
| Evidence sealing key management | See Key Management Policy |
| Retention policy enforcement | Evidence Manager |
| Evidence access control | Security Officer |
| Audit and compliance | Compliance Officer |

---

## 3. Evidence Lifecycle

### 3.1 Evidence Types

| Evidence Type | Trigger Event | Content | Retention |
|---------------|---------------|---------|-----------|
| Proof of Submission | Sender submits delivery | Sender ID, content hash, timestamp, recipient info | 10 years |
| Proof of Notification | Notification sent | Notification method, timestamp, content | 10 years |
| Proof of Availability | Content made available | Availability timestamp, access URL hash | 10 years |
| Proof of Receipt | Recipient accepts | Recipient ID, acceptance timestamp, content hash | 10 years |
| Proof of Refusal | Recipient refuses | Refusal timestamp, reason (if any) | 10 years |
| Proof of Negligence | Acceptance period expires | Expiry timestamp, notification history | 10 years |

### 3.2 Evidence Generation

**Requirements** (per REQ-C01):
- Every legally relevant event MUST generate evidence
- Evidence MUST be generated at the time of the event
- Evidence MUST contain sufficient information to reconstruct the timeline

**Platform Implementation**:
- See `src/qerds/services/evidence_service.py` for evidence generation
- See `specs/implementation/50-evidence-generation.md` for detailed specification

### 3.3 Evidence Sealing

**Requirements** (per REQ-C02):
- Evidence MUST be sealed with qualified electronic seal
- Seal MUST be applied at or near the time of evidence generation
- Seal MUST bind the evidence content to the service provider

**Platform Implementation**:
- Evidence sealed via Trust Service component
- See `docs/policies/key-management.md` for seal key management

### 3.4 Timestamping

**Requirements** (per REQ-C03):
- Evidence MUST carry a trustworthy time reference
- Timestamps MUST be from a qualified timestamp service
- Timestamp precision and accuracy MUST meet service requirements

**Platform Implementation**:
- Qualified timestamps applied to all evidence
- See Trust Service configuration for timestamp provider

---

## 4. Evidence Format and Interoperability

### 4.1 Evidence Format

**Requirements** (per REQ-C04):
- Evidence structures MUST follow ETSI EN 319 522-4 format
- Evidence MUST be machine-verifiable
- Evidence MUST be self-contained for verification

**Format Specifications**:
- Evidence structure: ETSI EN 319 522-4 compliant
- Signature format: XAdES/CAdES as appropriate
- Timestamp format: RFC 3161

### 4.2 Human-Readable Evidence

**Requirements** (per REQ-F07):
- Human-readable PDF versions MUST be generated
- PDFs MUST contain all legally required information
- PDFs MUST be compliant with CPCE/LRE requirements

**PDF Content**:
- Provider identification
- Delivery identification
- Event type and timestamp
- Relevant party information
- Verification information

---

## 5. Evidence Protection

### 5.1 Integrity Protection

**Requirements** (per REQ-C05):
- Evidence MUST be tamper-evident
- Any modification MUST be detectable
- Protection MUST persist for entire retention period

**Controls**:
- Cryptographic seal on all evidence
- Immutable storage once finalized
- Hash chain verification

### 5.2 Confidentiality

**Requirements** (per REQ-E01):
- Evidence containing sensitive data MUST be protected
- Access MUST be controlled based on authorization

**Controls**:
- Evidence encrypted at rest
- Access control per authorization rules
- Audit logging of all access

### 5.3 Availability

**Requirements**:
- Evidence MUST be retrievable for entire retention period
- Backup and recovery controls MUST be in place

**Controls**:
- Redundant storage
- Regular backup verification
- See `docs/policies/business-continuity.md`

---

## 6. Evidence Retention

### 6.1 Retention Periods

> **TODO**: Confirm retention periods meet legal requirements.

| Evidence Category | Minimum Retention | Legal Basis |
|-------------------|-------------------|-------------|
| All delivery evidence | 10 years | eIDAS, qualified TSP obligations |
| Proof of receipt (LRE) | 1 year minimum, 10 years recommended | CPCE R.53-4 |
| Audit logs | 10 years | ETSI EN 319 401 |
| Key ceremony records | 10 years + 5 years after key destruction | Internal policy |

### 6.2 Retention Controls

**Platform Support** (per REQ-H02):
- Retention periods enforced by platform
- No deletion before retention expiry
- Authorized disposal after retention period

**Procedures**:
- TODO: Retention verification process
- TODO: Disposal authorization process
- TODO: Disposal documentation

### 6.3 Long-Term Preservation

**Requirements**:
- Evidence MUST remain verifiable for entire retention period
- Signature/seal algorithms MUST remain secure
- Migration strategy for algorithm deprecation

**Controls**:
- Monitor ENISA algorithm guidance
- Plan for evidence re-sealing if algorithms deprecated
- Archive validation keys and certificates

---

## 7. Evidence Access and Retrieval

### 7.1 Access Authorization

| Requester | Access Rights | Authorization |
|-----------|---------------|---------------|
| Sender | Own delivery evidence | Authenticated sender |
| Recipient | Own delivery evidence | Authenticated recipient |
| Provider staff | All evidence (operational) | Role-based access |
| Auditors | Sample evidence | Audit engagement |
| Supervisory body | All evidence | Regulatory authority |
| Courts/legal | Specific evidence | Legal order |

### 7.2 Retrieval Procedures

**Self-Service Access**:
- Parties access evidence via authenticated portal
- Evidence available for download in machine and human-readable formats
- Access logged in audit trail

**Operational Access**:
- TODO: Staff access procedure
- TODO: Authorization requirements
- TODO: Audit logging

**Legal/Regulatory Access**:
- TODO: Legal request handling procedure
- TODO: Authorization verification
- TODO: Data minimization controls

### 7.3 Verification Services

**Requirements** (per REQ-F01):
- Third parties MUST be able to verify evidence
- Verification MUST use unique identifier
- Verification MUST not require recipient authentication

**Platform Support**:
- Public verification endpoint
- Verification by evidence ID
- Returns verification status without revealing content

---

## 8. Evidence for Disputes

### 8.1 Dispute Resolution Support

**Platform Support** (per REQ-H10):
- Timeline reconstruction for any delivery
- Evidence chain verification
- Controlled disclosure exports

### 8.2 Evidence Export

**Export Format**:
- Complete evidence bundle
- Verification instructions
- Certificate chain for seal verification

**Procedures**:
- TODO: Export authorization process
- TODO: Data minimization review
- TODO: Export documentation

---

## 9. Audit and Compliance

### 9.1 Evidence Audit

| Audit Type | Frequency | Scope |
|------------|-----------|-------|
| Integrity verification | Daily (automated) | Sample of recent evidence |
| Completeness check | Weekly | Evidence for all deliveries |
| Retention compliance | Monthly | Retention period verification |
| Full audit | Annual | All evidence controls |

### 9.2 Audit Pack Support

**Platform Support** (per REQ-H01):
- Export audit pack with evidence samples
- Include verification data
- Include system configuration snapshot

---

## 10. Operational Procedures

### 10.1 Evidence Generation Monitoring

> **TODO**: Document monitoring procedures.

- Monitor evidence generation success rates
- Alert on generation failures
- Alert on sealing/timestamping failures

### 10.2 Storage Monitoring

> **TODO**: Document storage monitoring.

- Monitor storage capacity
- Monitor storage integrity
- Alert on storage issues

### 10.3 Incident Handling

Evidence-related incidents are handled per the Incident Response Policy.

**Evidence-Specific Concerns**:
- Evidence integrity compromise
- Evidence unavailability
- Seal key compromise (see Key Management Policy)

---

## 11. Policy Review

### 11.1 Review Schedule

| Review Type | Frequency | Responsible |
|-------------|-----------|-------------|
| Policy review | Annual minimum | Evidence Manager |
| Retention review | Annual | Compliance Officer |
| Format/interoperability review | Per standard updates | Service Manager |

### 11.2 Change Triggers

This policy MUST be reviewed when:

- Changes to eIDAS or CPCE requirements
- Changes to ETSI EN 319 522 standards
- After evidence-related incidents
- Changes to evidence format or structure

---

## 12. Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | TODO | TODO | Initial template created |
| | | | |
| | | | |

---

## 13. Approval

> **TODO**: This policy MUST be formally approved before the service can be qualified.

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Evidence Manager | | | |
| Security Officer | | | |
| Compliance Officer | | | |

---

## Appendix A: Evidence Fields Reference

### Proof of Submission

| Field | Description | Required |
|-------|-------------|----------|
| evidence_id | Unique evidence identifier | Yes |
| delivery_id | Associated delivery | Yes |
| sender_id | Sender identifier | Yes |
| recipient_address | Recipient address | Yes |
| content_hash | Hash of delivery content | Yes |
| submission_timestamp | Timestamp of submission | Yes |
| seal | Provider seal | Yes |
| timestamp_token | Qualified timestamp | Yes |

### Proof of Receipt

| Field | Description | Required |
|-------|-------------|----------|
| evidence_id | Unique evidence identifier | Yes |
| delivery_id | Associated delivery | Yes |
| recipient_id | Recipient identifier | Yes |
| receipt_timestamp | Timestamp of receipt | Yes |
| content_hash | Hash of delivery content | Yes |
| seal | Provider seal | Yes |
| timestamp_token | Qualified timestamp | Yes |

---

## Appendix B: Evidence Verification Checklist

```
EVIDENCE VERIFICATION CHECKLIST

Evidence ID:
Evidence Type:
Verification Date:
Verifier:

STRUCTURE VERIFICATION
[ ] Evidence format is valid (ETSI EN 319 522-4)
[ ] All required fields present
[ ] Field values syntactically valid

SEAL VERIFICATION
[ ] Seal is present
[ ] Seal signature valid
[ ] Seal certificate valid at time of sealing
[ ] Seal certificate chains to trusted root
[ ] Seal certificate not revoked

TIMESTAMP VERIFICATION
[ ] Timestamp token present
[ ] Timestamp signature valid
[ ] Timestamp certificate valid
[ ] Timestamp certificate chains to trusted TSA

CONTENT VERIFICATION
[ ] Content hash matches (if content available)
[ ] Evidence references valid

RESULT
[ ] VALID - All checks passed
[ ] INVALID - Specify failure: _______________
```

---

## References

- `specs/requirements.md` - Requirement specifications
- `specs/implementation/50-evidence-generation.md` - Evidence generation specification
- `docs/policies/key-management.md` - Key Management Policy
- `docs/policies/security-policy.md` - Security Policy
- `docs/policies/business-continuity.md` - Business Continuity Policy
