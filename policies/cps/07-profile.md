# CPS Section 7: Certificate, CRL, and Evidence Profiles

**Document Status**: SKELETON
**Classification**: Published
**Covers**: REQ-C02, REQ-C04

## 7.1 Certificate Profile

### 7.1.1 Provider Seal Certificate Profile

[TODO: Define seal certificate profile]

| Field | Value/Requirement |
|-------|-------------------|
| Version | 3 (X.509 v3) |
| Serial Number | Unique per CA |
| Signature Algorithm | [TODO: Per specs/implementation/40-evidence-crypto-and-time.md] |
| Issuer | [TODO: Qualified TSP DN] |
| Validity | [TODO: Operational period] |
| Subject | [TODO: Provider DN] |
| Public Key | [TODO: Algorithm and size] |
| Extensions | [TODO: Required extensions] |

### 7.1.2 Version Number

X.509 Version 3

### 7.1.3 Certificate Extensions

[TODO: Define required extensions]

| Extension | Critical | Value |
|-----------|----------|-------|
| Key Usage | Yes | [TODO] |
| Extended Key Usage | No | [TODO] |
| [TODO: Others] | [TODO] | [TODO] |

### 7.1.4 Algorithm OIDs

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md` for algorithm specifications.

### 7.1.5 Name Constraints

[TODO: Define if applicable]

### 7.1.6 Certificate Policy OID

[TODO: Define policy OID]

### 7.1.7 Policy Qualifiers

[TODO: Define policy qualifiers]

## 7.2 CRL Profile

### 7.2.1 CRL Version

[TODO: Define CRL version]

### 7.2.2 CRL and Entry Extensions

[TODO: Define CRL extensions]

## 7.3 OCSP Profile

### 7.3.1 OCSP Version

[TODO: Define OCSP version]

### 7.3.2 OCSP Extensions

[TODO: Define OCSP extensions]

## 7.4 Evidence Profile

**Covers**: REQ-C04

### 7.4.1 Evidence Format

Evidence MUST follow ETSI EN 319 522 profiles as required by Implementing Regulation 2025/1944.

**Implementation**: See `specs/implementation/60-interop-and-verification.md` for evidence format requirements.

### 7.4.2 Evidence Types

| Evidence Type | Format Reference | Content Requirements |
|---------------|------------------|---------------------|
| Submission Receipt | [TODO: EN 319 522 reference] | [TODO] |
| Relay Receipt | [TODO] | [TODO] |
| Delivery Receipt | [TODO] | [TODO] |
| Non-Delivery Receipt | [TODO] | [TODO] |
| Refusal Receipt | [TODO] | [TODO] |

### 7.4.3 Evidence Sealing

Evidence MUST be sealed with:

- Provider's qualified seal (qualified mode)
- Qualified timestamp

**Implementation**: See `specs/implementation/40-evidence-crypto-and-time.md`.

### 7.4.4 Evidence Content

[TODO: Define evidence content requirements]

Evidence MUST include:

- Event type identifier
- Timestamp (qualified)
- Party identifiers (sender/recipient as appropriate)
- Content hash (where applicable)
- Service provider seal
- Policy version reference

### 7.4.5 Human-Readable Evidence

**Covers**: REQ-F07

For LRE, human-readable proofs (PDF) MUST be generated.

**Implementation**: See `specs/implementation/30-lifecycle-and-evidence.md` for proof requirements.

## 7.5 ETSI EN 319 522 Profile Selection

**Covers**: REQ-C04

### 7.5.1 Selected Profile

[TODO: Define which EN 319 522 profile is implemented]

**Implementation**: See `specs/implementation/65-etsi-interop-profile.md` for profile selection.

### 7.5.2 Interoperability

[TODO: Define interoperability requirements]

## Cross-References

- **Evidence Cryptography**: `specs/implementation/40-evidence-crypto-and-time.md`
- **Trust Services**: `specs/implementation/45-trust-services.md`
- **Interoperability**: `specs/implementation/60-interop-and-verification.md`
- **ETSI Profile**: `specs/implementation/65-etsi-interop-profile.md`
- **Lifecycle and Evidence**: `specs/implementation/30-lifecycle-and-evidence.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
