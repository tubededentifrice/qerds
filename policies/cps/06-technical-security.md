# CPS Section 6: Technical Security Controls

**Document Status**: SKELETON
**Classification**: Internal (summary may be published)
**Covers**: REQ-D03, REQ-D04, REQ-D07, REQ-E01

## 6.1 Key Pair Generation and Installation

### 6.1.1 Key Pair Generation

**Covers**: REQ-D04

[TODO: Define key generation requirements]

Key generation MUST:

- Use approved random number generators
- Be performed within HSM/QSCD (qualified mode)
- Follow ceremony procedures

**Implementation**: See `policies/key-management-policy.md` for key generation requirements.

### 6.1.2 Private Key Delivery

Private keys are NEVER delivered or exported from secure storage.

### 6.1.3 Public Key Delivery

[TODO: Define public key delivery]

### 6.1.4 Key Sizes

**Covers**: REQ-D03

Key sizes MUST follow "state of the art" per Implementing Regulation 2025/1944.

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md` for algorithm requirements.

### 6.1.5 Key Generation Hardware

**Covers**: REQ-D04

Qualified keys MUST be generated in certified HSM/QSCD.

### 6.1.6 Key Usage Purposes

[TODO: Define key usage restrictions]

## 6.2 Private Key Protection and Cryptographic Module Engineering

### 6.2.1 Cryptographic Module Standards

**Covers**: REQ-D04

Cryptographic modules MUST meet:

- [TODO: Certification requirements per Implementing Regulation 2025/1944]

### 6.2.2 Private Key Multi-person Control

[TODO: Define multi-person control]

Sensitive key operations require M of N control.

### 6.2.3 Private Key Escrow

[TODO: Define escrow policy]

### 6.2.4 Private Key Backup

[TODO: Define backup policy]

**Implementation**: See `policies/key-management-policy.md`.

### 6.2.5 Private Key Archival

[TODO: Define archival policy]

### 6.2.6 Private Key Transfer

Private key transfer (if permitted):

- [TODO: Define requirements]

### 6.2.7 Private Key Storage

**Covers**: REQ-D04

Private keys MUST be stored in HSM/QSCD (qualified mode).

### 6.2.8 Method of Activating Private Key

[TODO: Define activation requirements]

### 6.2.9 Method of Deactivating Private Key

[TODO: Define deactivation procedures]

### 6.2.10 Method of Destroying Private Key

[TODO: Define destruction procedures]

**Implementation**: See `policies/key-management-policy.md`.

## 6.3 Other Aspects of Key Pair Management

### 6.3.1 Public Key Archival

[TODO: Define public key archival]

### 6.3.2 Certificate/Key Operational Periods

[TODO: Define operational periods]

## 6.4 Activation Data

### 6.4.1 Activation Data Generation

[TODO: Define activation data generation]

### 6.4.2 Activation Data Protection

[TODO: Define protection requirements]

### 6.4.3 Other Aspects

[TODO: Other activation data considerations]

## 6.5 Computer Security Controls

### 6.5.1 Computer Security Requirements

[TODO: Define computer security requirements]

**Implementation**: See `specs/implementation/90-security-and-ops-controls.md`.

### 6.5.2 Computer Security Rating

[TODO: Define security rating requirements]

## 6.6 Lifecycle Technical Controls

### 6.6.1 System Development Controls

[TODO: Define SDLC security requirements]

### 6.6.2 Security Management Controls

**Implementation**: See `policies/security-policy.md`.

### 6.6.3 Lifecycle Security Controls

[TODO: Define lifecycle controls]

## 6.7 Network Security Controls

**Covers**: REQ-D07

### 6.7.1 Network Architecture

[TODO: Reference architecture]

**Implementation**: See `specs/implementation/05-architecture.md` for trust boundaries.

### 6.7.2 Firewall Configuration

Default-deny network controls with explicit allowlists.

**Implementation**: See `specs/implementation/90-security-and-ops-controls.md`.

### 6.7.3 Network Monitoring

[TODO: Define monitoring requirements]

## 6.8 Time-Stamping

**Covers**: REQ-C03

### 6.8.1 Time Source

[TODO: Define time source requirements]

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md` for timestamp requirements.

### 6.8.2 Time Accuracy

[TODO: Define accuracy requirements]

## 6.9 Data Confidentiality

**Covers**: REQ-E01

### 6.9.1 Encryption at Rest

All sensitive data encrypted at rest using strong symmetric encryption.

**Implementation**: See `specs/implementation/90-security-and-ops-controls.md` for encryption strategy.

### 6.9.2 Encryption in Transit

All communications encrypted using TLS.

### 6.9.3 Key Management for Data Encryption

KEK managed by qerds-trust service.
DEKs generated per object/delivery.

**Implementation**: See `specs/implementation/90-security-and-ops-controls.md`.

## Cross-References

- **Key Management Policy**: `policies/key-management-policy.md`
- **Security Policy**: `policies/security-policy.md`
- **Architecture**: `specs/implementation/05-architecture.md`
- **Cryptographic Requirements**: `specs/implementation/40-evidence-crypto-and-time.md`
- **Trust Services**: `specs/implementation/45-trust-services.md`
- **Security Controls**: `specs/implementation/90-security-and-ops-controls.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
