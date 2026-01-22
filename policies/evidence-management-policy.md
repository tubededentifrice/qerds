# Evidence Management Policy

**Document Status**: SKELETON
**Classification**: Internal (summary may be published)
**Covers**: REQ-C01, REQ-C02, REQ-C03, REQ-C05, REQ-H02, REQ-F05

## 1. Purpose and Scope

[TODO: Define the purpose and scope of this evidence management policy]

This policy establishes evidence creation, sealing, retention, and access requirements for the QERDS/LRE service, ensuring alignment with:

- ETSI EN 319 521 evidence requirements
- ETSI EN 319 522 evidence format and interoperability
- Implementing Regulation (EU) 2025/1944
- France CPCE (LRE evidence requirements)

**Implementation**: See `specs/implementation/30-lifecycle-and-evidence.md` for evidence event definitions and `specs/implementation/40-evidence-crypto-and-time.md` for evidence cryptography.

## 2. Evidence Types

### 2.1 Evidence Event Coverage

**Covers**: REQ-C01

Every legally relevant lifecycle event MUST generate evidence.

**Implementation**: See `specs/implementation/30-lifecycle-and-evidence.md` for complete event list:

- Submission/deposit events
- Acceptance events
- Notification events
- Availability events
- Receipt events
- Refusal events
- Non-claim/expiry events

### 2.2 Evidence Artifacts

[TODO: Document evidence artifact types]

| Event Type | Evidence Artifact | Format |
|------------|-------------------|--------|
| Deposit | Proof of deposit | [TODO: Reference spec] |
| Receipt | Proof of receipt | [TODO: Reference spec] |
| Refusal | Proof of refusal | [TODO: Reference spec] |
| Non-claim | Proof of negligence | [TODO: Reference spec] |

**Implementation**: See `specs/implementation/60-interop-and-verification.md` for evidence format requirements.

## 3. Evidence Creation

### 3.1 Creation Requirements

Evidence MUST:

- Be created at the time of the event (not retroactively)
- Include all legally required information
- Reference the policy version in effect

### 3.2 Evidence Authenticity

**Covers**: REQ-C02

Evidence MUST be:

- Protected against forgery
- Attributable to the service provider (via seal/signature)

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md` for sealing requirements.

### 3.3 Trusted Time

**Covers**: REQ-C03

Evidence MUST carry a trustworthy time reference.

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md` for timestamp requirements.

## 4. Evidence Sealing

### 4.1 Sealing Process

[TODO: Document sealing process at high level]

**Implementation**: See `specs/implementation/45-trust-services.md` for qerds-trust service sealing operations.

### 4.2 Qualified vs Non-Qualified Sealing

Per REQ-G02:

- **Qualified mode**: Evidence sealed with qualified seal, qualified timestamp
- **Non-qualified mode**: Evidence clearly marked as non-qualified

**Implementation**: See `specs/implementation/10-claims-and-modes.md` for mode enforcement.

## 5. Evidence Immutability

**Covers**: REQ-C05

### 5.1 Tamper-Evidence Requirements

Evidence MUST be:

- Tamper-evident
- Protected against undetected modification
- Protected against undetected deletion

### 5.2 Implementation

**Implementation**: See `specs/implementation/50-audit-logging-and-immutability.md` for immutability mechanisms.

## 6. Evidence Retention

**Covers**: REQ-H02, REQ-F05

### 6.1 Retention Periods

[TODO: Define retention periods by evidence type]

| Evidence Type | Minimum Retention | Legal Basis |
|---------------|-------------------|-------------|
| Proof of receipt (LRE) | 1 year minimum | CPCE |
| [TODO: Other types] | [TODO] | [TODO] |

### 6.2 Retention Controls

The platform MUST support:

- Configurable retention periods
- Automated retention enforcement
- Audit trails for retention actions

**Implementation**: See `specs/implementation/70-storage-and-retention.md` for retention implementation.

### 6.3 Verification Data Retention

Verification data needed to validate evidence MUST be retained alongside the evidence:

- Certificate chains
- Revocation information
- Timestamp tokens

## 7. Evidence Access

### 7.1 Access Control

Evidence access MUST be controlled:

- Sender: access to evidence for their deliveries
- Recipient: access to evidence for deliveries they received
- Authorized third parties: verification access per CPCE REQ-F01
- Auditors: controlled access for conformity assessment

### 7.2 Human-Readable Evidence

**Covers**: REQ-F07

For LRE, human-readable evidence artifacts (e.g., PDF proofs) MUST be generated.

**Implementation**: See `specs/implementation/30-lifecycle-and-evidence.md` for human-readable proof requirements.

## 8. Evidence Retrieval and Verification

### 8.1 Retrieval

Evidence MUST be retrievable for:

- The full retention period
- Audit pack generation
- Dispute resolution

**Implementation**: See `specs/implementation/70-storage-and-retention.md` for storage requirements.

### 8.2 Verification

Evidence MUST be independently verifiable:

- Signature/seal verification
- Timestamp verification
- Integrity verification

**Implementation**: See `specs/implementation/60-interop-and-verification.md` for verification interface.

## 9. Evidence for Disputes

**Covers**: REQ-H10

The platform MUST support generating dispute-resolution artifacts:

- Full event timeline
- Evidence chain
- Verification outputs
- Controlled disclosure (redaction where required)

**Implementation**: See `specs/implementation/80-audit-and-conformity.md` for dispute export requirements.

## 10. Policy Version Reference

Evidence objects MUST reference the policy version in effect at creation time.

**Implementation**: See `specs/implementation/80-audit-and-conformity.md` for policy version tracking.

## 11. Roles and Responsibilities

[TODO: Define evidence management roles]

| Role | Responsibilities |
|------|-----------------|
| Evidence Administrator | [TODO] |
| Retention Manager | [TODO] |

## 12. Policy Review

[TODO: Define review frequency]

This policy MUST be reviewed:

- At least annually
- When evidence format standards change
- When retention requirements change

## Cross-References

- **Lifecycle and Evidence Events**: `specs/implementation/30-lifecycle-and-evidence.md`
- **Evidence Cryptography**: `specs/implementation/40-evidence-crypto-and-time.md`
- **Trust Services**: `specs/implementation/45-trust-services.md`
- **Immutability**: `specs/implementation/50-audit-logging-and-immutability.md`
- **Interoperability**: `specs/implementation/60-interop-and-verification.md`
- **Storage and Retention**: `specs/implementation/70-storage-and-retention.md`
- **Audit Packs**: `specs/implementation/80-audit-and-conformity.md`
- **Key Management Policy**: `policies/key-management-policy.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
