# Key Management Policy

**Document ID**: POL-KEY-001
**Version**: 0.1 (TEMPLATE)
**Classification**: Confidential
**Covers**: REQ-D03 (Cryptographic mechanisms), REQ-D04 (Secure key storage), REQ-H07 (Key lifecycle ceremony evidence), REQ-A03 (Policies and CPS)

> **NOTICE**: This is a placeholder policy document. The provider MUST complete all TODO sections with operational details before the service can be considered qualified under eIDAS/ETSI EN 319 401/521.

---

## 1. Scope and Purpose

### 1.1 Scope

This policy applies to all cryptographic keys and related material used in the QERDS service, including:

- Qualified electronic seal keys (for evidence sealing)
- TLS/transport encryption keys
- Data encryption keys (content protection)
- HMAC/authentication keys
- Any other cryptographic material

### 1.2 Purpose

This Key Management Policy establishes the controls for the complete lifecycle of cryptographic keys used in the QERDS service. It ensures:

- Keys are generated securely using approved methods
- Keys are protected against unauthorized access and compromise
- Key usage is appropriate and auditable
- Key ceremonies are witnessed and documented
- Compliance with eIDAS and ETSI requirements for qualified keys

### 1.3 Normative References

- Regulation (EU) No 910/2014 (eIDAS)
- Commission Implementing Regulation (EU) 2025/1944
- ETSI EN 319 401 (Section 7.8 - Cryptographic controls)
- ETSI EN 319 521 (Section 6.6 - Cryptographic controls for ERDS)
- ENISA State of the Art Cryptographic Mechanisms (current version)
- CEN EN 419 221 (Cryptographic modules for TSPs) - where applicable

---

## 2. Roles and Responsibilities

> **TODO**: The provider MUST define the specific individuals or roles for key management.

### 2.1 Key Management Roles

| Role | Responsibilities | Assigned To |
|------|------------------|-------------|
| Key Management Officer | Policy ownership, ceremony oversight | TODO |
| Key Custodian (Primary) | Key share holder, ceremony participant | TODO |
| Key Custodian (Backup) | Key share holder, ceremony participant | TODO |
| System Administrator | Technical key operations | TODO |
| Security Officer | Key security oversight | TODO |

### 2.2 Separation of Duties

The following operations MUST require multiple authorized personnel:

| Operation | Minimum Participants | Roles Required |
|-----------|---------------------|----------------|
| Key generation ceremony | 2 | Key Management Officer + Key Custodian |
| Key activation | 2 | Key Custodian + Security Officer |
| Key revocation | 2 | Key Management Officer + Security Officer |
| Key destruction | 2 | Key Custodian + Security Officer |

---

## 3. Key Inventory

> **TODO**: The provider MUST maintain a key inventory.

### 3.1 Key Types and Classification

| Key Type | Purpose | Algorithm | Classification | Storage |
|----------|---------|-----------|----------------|---------|
| Qualified seal key | Evidence sealing | TODO | Critical | HSM/QSCD |
| Timestamp seal key | Timestamp tokens | TODO | Critical | HSM/QSCD |
| TLS server key | Transport security | TODO | High | Secure file/HSM |
| Database encryption key | Data-at-rest | TODO | High | Secure file/HSM |
| Content encryption keys | Delivery content | TODO | High | Database (encrypted) |
| HMAC keys | Audit log chaining | TODO | High | Secure file |

### 3.2 Key Inventory Records

For each key, maintain:

- Unique key identifier
- Key type and algorithm
- Creation date and ceremony reference
- Activation date
- Expiration date
- Current status (pending, active, suspended, revoked, destroyed)
- Storage location
- Associated certificates (if applicable)

---

## 4. Cryptographic Requirements

### 4.1 Approved Algorithms

> **TODO**: Confirm algorithms meet current ENISA guidance.

Per REQ-D03, all cryptographic mechanisms MUST follow state-of-the-art guidance:

| Purpose | Algorithm | Key Size | Notes |
|---------|-----------|----------|-------|
| Digital signature (seal) | ECDSA or EdDSA | P-256/P-384 or Ed25519/Ed448 | Per ENISA guidance |
| Symmetric encryption | AES-GCM | 256-bit | Content encryption |
| Key derivation | HKDF-SHA256 | N/A | Key derivation |
| Hash function | SHA-256/SHA-384 | N/A | Hashing |
| Random generation | CSPRNG | N/A | Per platform/HSM |

### 4.2 Prohibited Algorithms

The following MUST NOT be used:

- MD5 (any purpose)
- SHA-1 (any purpose)
- DES/3DES
- RSA < 2048 bits
- Any algorithm not on the approved list

---

## 5. Key Lifecycle

### 5.1 Key Generation

> **TODO**: Document specific key generation procedures.

**Requirements**:
- Qualified seal keys MUST be generated within a QSCD/HSM (per REQ-D04)
- Generation MUST use approved random number generators
- Generation ceremony MUST be witnessed and documented

**Generation Ceremony Outline**:
1. Schedule ceremony with required participants
2. Verify identity of all participants
3. Initialize secure environment
4. Generate key pair
5. Verify key generation success
6. Create and distribute key shares (if applicable)
7. Document ceremony in ceremony log
8. Store ceremony evidence

### 5.2 Key Activation

> **TODO**: Document specific key activation procedures.

**Requirements**:
- Keys MUST NOT be used until formally activated
- Activation requires approval from Key Management Officer
- Activation MUST be recorded

**Activation Criteria**:
- Generation ceremony completed and verified
- Associated certificates issued (if applicable)
- Testing completed in non-production environment
- Approval obtained from required parties

### 5.3 Key Usage

**Operational Controls**:
- Keys used only for intended purpose
- Usage logged in audit trail
- Anomalous usage triggers alerts

**Access Control**:
- Access to keys requires authentication
- Access logged and auditable
- Principle of least privilege applied

### 5.4 Key Rotation

> **TODO**: Document key rotation schedule and procedures.

| Key Type | Rotation Period | Procedure |
|----------|-----------------|-----------|
| Qualified seal key | Per certificate validity | New ceremony |
| TLS server key | Annual | Certificate renewal |
| Database encryption key | Annual | Re-encryption |
| Content encryption keys | Per delivery | Automatic |
| HMAC keys | TODO | TODO |

### 5.5 Key Suspension

**Suspension Triggers**:
- Suspected compromise
- Security incident investigation
- Compliance issue

**Suspension Procedure**:
1. Immediately disable key in operational systems
2. Notify Security Officer
3. Investigate root cause
4. Determine if revocation required
5. Document in key register

### 5.6 Key Revocation

> **TODO**: Document key revocation procedures.

**Revocation Triggers**:
- Confirmed compromise
- End of validity period
- Policy violation
- Organizational change

**Revocation Procedure**:
1. Obtain authorization from Key Management Officer + Security Officer
2. Disable key in all systems
3. Publish revocation (CRL/OCSP if applicable)
4. Update key inventory
5. Document revocation
6. Initiate key generation for replacement (if needed)

### 5.7 Key Destruction

> **TODO**: Document key destruction procedures.

**Destruction Requirements**:
- All copies of key material MUST be destroyed
- Destruction MUST be witnessed
- Destruction MUST be documented
- Backups containing key material MUST be addressed

**Destruction Methods**:
- HSM: Use HSM key deletion function
- File-based: Secure erase + physical destruction of media

---

## 6. Key Storage

### 6.1 Qualified Seal Keys (Critical)

Per REQ-D04, qualified seal keys MUST be:

- Generated within certified secure cryptographic device (QSCD)
- Stored within QSCD at all times
- Never exported in plaintext
- Protected by multi-party access control

> **TODO**: Document specific QSCD/HSM details.

**HSM/QSCD Details**:
- Device: TODO (model, certification)
- Location: TODO
- Access control: TODO

### 6.2 Other Cryptographic Keys

| Key Type | Storage Method | Protection |
|----------|---------------|------------|
| TLS keys | TODO | TODO |
| Database encryption | TODO | TODO |
| HMAC keys | TODO | TODO |

### 6.3 Key Backup

> **TODO**: Document key backup procedures.

**Backup Requirements**:
- Backup keys encrypted with backup key
- Backup stored in separate secure location
- Backup tested for recoverability
- Backup access audited

---

## 7. Ceremony Procedures

### 7.1 Ceremony Environment

> **TODO**: Document secure ceremony environment.

**Physical Requirements**:
- TODO: Secure room requirements
- TODO: Access control
- TODO: Surveillance

**Technical Requirements**:
- TODO: Isolated network
- TODO: Verified software
- TODO: Audit logging

### 7.2 Ceremony Documentation

Each ceremony MUST produce:

- Ceremony script (signed by participants)
- Attendance log with identity verification
- Ceremony execution log
- Key identifier and public key (if applicable)
- Video recording (if required by policy)
- Signed ceremony report

### 7.3 Ceremony Evidence

Per REQ-H07, the platform MUST support producing evidence of key lifecycle events:

- Generation ceremonies
- Activation records
- Rotation records
- Revocation records
- Destruction records

---

## 8. Incident Response

### 8.1 Key Compromise Response

If key compromise is suspected:

1. **Immediate**: Suspend key in all systems
2. **Notify**: Security Officer and Key Management Officer
3. **Assess**: Determine scope and impact
4. **Contain**: Prevent further unauthorized use
5. **Recover**: Revoke and replace key if confirmed
6. **Document**: Full incident report

**Reference**: See `docs/policies/incident-response.md`

### 8.2 Impact Assessment

For evidence sealing key compromise:

- Identify all evidence sealed with compromised key
- Assess integrity impact
- Notify affected parties if required
- Consider re-sealing with new key (where possible)

---

## 9. Compliance and Audit

### 9.1 Audit Trail

All key operations MUST be logged:

- Key generation
- Key activation/deactivation
- Key usage (signing operations)
- Key access
- Key revocation
- Key destruction

### 9.2 Audit Reviews

| Review Type | Frequency | Reviewer |
|-------------|-----------|----------|
| Key inventory review | Quarterly | Key Management Officer |
| Access log review | Monthly | Security Officer |
| Ceremony log review | After each ceremony | Key Management Officer |
| Policy compliance | Annual | External auditor |

---

## 10. Policy Review

### 10.1 Review Schedule

| Review Type | Frequency | Responsible |
|-------------|-----------|-------------|
| Policy review | Annual minimum | Key Management Officer |
| Algorithm review | Annual | Security Officer |
| Inventory review | Quarterly | Key Management Officer |

### 10.2 Change Triggers

This policy MUST be reviewed when:

- Changes to ENISA cryptographic guidance
- Changes to eIDAS requirements
- After any key-related incident
- New key types introduced
- HSM/QSCD changes

---

## 11. Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | TODO | TODO | Initial template created |
| | | | |
| | | | |

---

## 12. Approval

> **TODO**: This policy MUST be formally approved before the service can be qualified.

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Key Management Officer | | | |
| Security Officer | | | |
| Executive Sponsor | | | |

---

## Appendix A: Key Ceremony Log Template

```
KEY CEREMONY LOG

Ceremony Type: [ ] Generation [ ] Activation [ ] Revocation [ ] Destruction
Date:
Location:
Ceremony ID:

PARTICIPANTS
| Name | Role | ID Verified | Signature |
|------|------|-------------|-----------|
|      |      |             |           |
|      |      |             |           |

KEY DETAILS
Key Identifier:
Key Type:
Algorithm:
Purpose:

CEREMONY STEPS
[ ] Environment verified secure
[ ] Participants authenticated
[ ] Equipment verified
[ ] Ceremony script followed
[ ] Key operation completed
[ ] Results verified
[ ] Documentation complete

RESULTS
Outcome: [ ] Success [ ] Failure
Public Key (if applicable):
Certificate ID (if applicable):
Notes:

ATTESTATION
We attest that this ceremony was conducted in accordance with the Key Management Policy.

Signature (Key Management Officer): _________________ Date: _______
Signature (Key Custodian): _________________ Date: _______
```

---

## References

- `specs/requirements.md` - Requirement specifications
- `docs/policies/security-policy.md` - Security Policy
- `docs/policies/incident-response.md` - Incident Response Policy
- ENISA Algorithms and Key Sizes (current version)
