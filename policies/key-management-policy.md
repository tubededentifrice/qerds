# Key Management Policy

**Document Status**: SKELETON
**Classification**: Internal (operational details confidential)
**Covers**: REQ-D04, REQ-H07, REQ-D03

## 1. Purpose and Scope

[TODO: Define the purpose and scope of this key management policy]

This policy establishes key lifecycle management requirements for the QERDS/LRE service, ensuring alignment with:

- ETSI EN 319 401 Section 7.5 (Cryptographic controls)
- ETSI EN 319 521 key management requirements
- Implementing Regulation (EU) 2025/1944 (secure key storage)
- ENISA cryptographic guidance

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md` for cryptographic algorithms and `specs/implementation/45-trust-services.md` for trust service implementation.

## 2. Key Types and Classification

### 2.1 Key Inventory

[TODO: Define complete key inventory]

| Key Type | Purpose | Storage | Lifecycle Owner |
|----------|---------|---------|-----------------|
| Provider Seal Key | Evidence sealing | HSM/QSCD (qualified mode) | [TODO] |
| KEK (Key Encryption Key) | Data-at-rest encryption | HSM/QSCD | [TODO] |
| DEK (Data Encryption Key) | Per-object encryption | Database (wrapped) | [TODO] |
| TLS Keys | Transport security | [TODO] | [TODO] |
| [TODO: Additional keys] | [TODO] | [TODO] | [TODO] |

### 2.2 Qualified vs Non-Qualified Keys

Per REQ-D04 and REQ-G02:

- **Qualified mode**: Private keys for qualified evidence MUST be generated/stored/used within certified secure cryptographic devices (HSM/QSCD)
- **Non-qualified mode**: Software keys for dev/test only, clearly labeled as non-qualified

**Implementation**: See `specs/implementation/45-trust-services.md` for qualified/non-qualified mode handling.

## 3. Key Generation

**Covers**: REQ-H07

### 3.1 Generation Requirements

[TODO: Define key generation requirements]

Key generation MUST:

- Use approved random number generators
- Follow algorithm requirements in `specs/implementation/40-evidence-crypto-and-time.md`
- Be performed within the secure cryptographic device (for qualified keys)
- Be witnessed and documented (ceremony)

### 3.2 Generation Ceremony

[TODO: Define key generation ceremony requirements]

Ceremony MUST include:

- Multi-person control (M of N)
- Video recording (if required)
- Ceremony script and checklist
- Signed ceremony log

Evidence of key generation ceremonies MUST be exportable for audits.

## 4. Key Storage

**Covers**: REQ-D04

### 4.1 Secure Storage Requirements

[TODO: Define storage requirements by key type]

Qualified signing keys MUST be stored in:

- Certified HSM/QSCD meeting applicable requirements
- With physical and logical access controls
- With tamper-evident mechanisms

### 4.2 KEK Management

The Key Encryption Key (KEK) for data-at-rest encryption:

**Implementation**: See `specs/implementation/90-security-and-ops-controls.md` for KEK custody by qerds-trust service.

### 4.3 Backup Key Storage

[TODO: Define backup key storage requirements]

- Geographic separation
- Equivalent security controls
- Recovery procedures

## 5. Key Usage

### 5.1 Usage Controls

[TODO: Define key usage controls]

Key usage MUST:

- Be limited to authorized purposes
- Be logged (audit trail)
- Require authentication/authorization

### 5.2 Operational Modes

**Qualified mode**:

- Keys accessed only through certified crypto module
- No software fallback permitted
- Evidence marked as qualified

**Non-qualified mode**:

- Software keys permitted
- Evidence clearly marked as non-qualified

**Implementation**: See `specs/implementation/10-claims-and-modes.md` for mode enforcement.

## 6. Key Rotation

### 6.1 Rotation Schedule

[TODO: Define rotation schedule by key type]

| Key Type | Rotation Period | Trigger Events |
|----------|-----------------|----------------|
| Provider Seal Key | [TODO] | Compromise, expiry, algorithm deprecation |
| KEK | [TODO] | [TODO] |
| TLS Keys | [TODO] | [TODO] |

### 6.2 Rotation Procedures

[TODO: Define rotation procedures]

Rotation MUST:

- Maintain service continuity
- Preserve ability to verify historical evidence
- Be documented with ceremony evidence

## 7. Key Revocation and Destruction

### 7.1 Revocation Triggers

[TODO: Define revocation triggers]

- Key compromise
- Personnel changes
- Algorithm deprecation
- End of operational life

### 7.2 Revocation Procedures

[TODO: Define revocation procedures]

### 7.3 Key Destruction

[TODO: Define destruction procedures]

Destruction MUST:

- Be irreversible
- Be witnessed and documented
- Follow secure destruction standards
- Consider evidence verification implications

## 8. Key Lifecycle Evidence

**Covers**: REQ-H07

The platform MUST support producing evidence of key lifecycle events:

- Generation ceremonies
- Activation records
- Usage logs
- Rotation ceremonies
- Revocation records
- Destruction certificates

**Implementation**: See `specs/implementation/80-audit-and-conformity.md` for audit pack key lifecycle requirements.

## 9. Cryptographic Algorithm Requirements

**Covers**: REQ-D03

Algorithm selection MUST follow "state of the art" per Implementing Regulation 2025/1944.

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md` for algorithm specifications.

## 10. Roles and Responsibilities

[TODO: Define key management roles]

| Role | Responsibilities |
|------|-----------------|
| Key Custodian | [TODO] |
| Security Officer | [TODO] |
| Ceremony Witness | [TODO] |

## 11. Policy Review

[TODO: Define review frequency]

This policy MUST be reviewed:

- At least annually
- When cryptographic guidance changes
- After key-related incidents
- When HSM/QSCD certification changes

## Cross-References

- **Cryptographic Algorithms**: `specs/implementation/40-evidence-crypto-and-time.md`
- **Trust Services**: `specs/implementation/45-trust-services.md`
- **Operational Modes**: `specs/implementation/10-claims-and-modes.md`
- **Security Controls**: `specs/implementation/90-security-and-ops-controls.md`
- **Audit Packs**: `specs/implementation/80-audit-and-conformity.md`
- **Security Policy**: `policies/security-policy.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
