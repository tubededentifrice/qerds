# Cryptographic Mechanisms

This document describes the cryptographic algorithm choices, key sizes, and parameters used in QERDS. It covers REQ-D03 (cryptographic mechanisms following state of the art).

## Overview

QERDS uses cryptographic mechanisms compliant with:
- **ENISA**: Algorithms, Key Sizes and Protocols (current edition)
- **NIST SP 800-57**: Recommendations for Key Management
- **BSI TR-02102**: Cryptographic Mechanisms (German Federal Office for Information Security)
- **NIST SP 800-38D**: Recommendation for Block Cipher Modes of Operation: GCM

All algorithm choices target at least 128-bit security strength, with most operations using 192-bit equivalent or higher.

## Algorithm Inventory

### Symmetric Encryption

| Algorithm | Standard | Key Size | Usage |
|-----------|----------|----------|-------|
| AES-256-GCM | NIST SP 800-38D | 256 bits | Content encryption (DEK) |
| AES-256-GCM | NIST SP 800-38D | 256 bits | Key wrapping (KEK protects DEK) |

**Implementation**: `src/qerds/services/encryption.py`

AES-256-GCM provides authenticated encryption with associated data (AEAD), ensuring both confidentiality and integrity in a single operation.

### Hash Functions

| Algorithm | Standard | Output Size | Usage |
|-----------|----------|-------------|-------|
| SHA-256 | FIPS 180-4 | 256 bits | Content digests, session token hashing |
| SHA-384 | FIPS 180-4 | 384 bits | Evidence sealing, timestamp message imprints |

**Implementation**:
- SHA-256: `src/qerds/services/encryption.py` (content hash verification)
- SHA-384: `src/qerds/services/trust.py` (sealing and timestamping)

SHA-384 is used for signing operations to match the security level of ECDSA P-384.

### Digital Signatures

| Algorithm | Standard | Key Size | Usage |
|-----------|----------|----------|-------|
| ECDSA P-384 | FIPS 186-4, RFC 5480 | 384 bits | Evidence sealing (provider attestation) |
| ECDSA P-384 | FIPS 186-4, RFC 5480 | 384 bits | Timestamping (time attestation) |

**Implementation**: `src/qerds/services/trust.py`

ECDSA with the P-384 curve provides approximately 192-bit security strength, exceeding ENISA recommendations for long-term protection of qualified trust service evidence.

### Key Derivation

| Algorithm | Standard | Usage |
|-----------|----------|-------|
| PBKDF2-HMAC-SHA256 | RFC 2898, NIST SP 800-132 | KEK encryption at rest (password-based) |
| HKDF-SHA256 | RFC 5869 | General key derivation (configured) |

**Implementation**: `src/qerds/services/encryption.py`

PBKDF2 iteration count is set to 600,000 per OWASP 2023 recommendations.

### Random Number Generation

| Source | Standard | Usage |
|--------|----------|-------|
| `os.urandom()` | Platform CSPRNG | DEK generation, nonce generation |
| `secrets` module | PEP 506 | Session tokens, OIDC state/nonce |
| `gen_random_uuid()` | PostgreSQL | Database UUIDs |

**Implementation**: Throughout the codebase

All random values are generated using cryptographically secure pseudo-random number generators (CSPRNG).

## Key Sizes and Parameters

### Symmetric Keys

| Key Type | Size | Notes |
|----------|------|-------|
| Data Encryption Key (DEK) | 256 bits (32 bytes) | Per-object, AES-256 |
| Key Encryption Key (KEK) | 256 bits (32 bytes) | Master key, AES-256 |
| HMAC keys | 256 bits (32 bytes) | Token signing |

### Asymmetric Keys

| Key Type | Size | Curve | Notes |
|----------|------|-------|-------|
| Signing key | 384 bits | NIST P-384 | Evidence sealing |
| Timestamping key | 384 bits | NIST P-384 | Time attestation |

### GCM Parameters

| Parameter | Size | Notes |
|-----------|------|-------|
| Nonce/IV | 96 bits (12 bytes) | Per NIST SP 800-38D |
| Authentication tag | 128 bits (16 bytes) | Full-length tag |

NIST SP 800-38D recommends 96-bit nonces for GCM when using deterministic construction. Each encryption operation generates a fresh random nonce.

### Certificate Validity

| Certificate Type | Validity Period |
|------------------|-----------------|
| Signing certificate | 730 days (2 years) |
| Timestamping certificate | 730 days (2 years) |

## Guidance References

### ENISA Algorithms, Key Sizes and Protocols

The algorithm choices align with ENISA's recommended algorithms for:
- **Near term (2025-2027)**: All algorithms in use are recommended
- **Long term (2028+)**: All algorithms remain suitable

Key reference points:
- AES-256: Recommended for confidentiality
- SHA-384/512: Recommended for integrity
- ECDSA P-384: Recommended for digital signatures

### NIST SP 800-57 Key Management

Key management practices follow NIST SP 800-57 Part 1 recommendations:
- **Key separation**: Different keys for different purposes (signing vs. timestamping vs. encryption)
- **Key lifecycle**: Generation, activation, rotation, retirement, revocation
- **Cryptoperiod**: Certificate validity periods align with recommendations

### BSI TR-02102 (German Guidance)

BSI TR-02102 recommendations are met:
- AES with 256-bit keys for symmetric encryption
- ECDSA with P-384 curve for signatures
- SHA-384 for hash operations matching signature security level

## Algorithm Versioning

Cryptographic configuration is versioned for audit traceability (REQ-A04):

```python
# src/qerds/core/config.py
class CryptoSettings:
    config_version: str = "2026.1"
    hash_algorithm: str = "sha256"
    signature_algorithm: str = "Ed25519"  # Note: trust.py uses ECDSA-P384
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation_algorithm: str = "HKDF-SHA256"
```

The `AlgorithmSuite` in `trust.py` tracks the actual signing algorithms:

```python
# src/qerds/services/trust.py
class AlgorithmSuite:
    version: str = "2026.1"
    hash_algorithm: str = "sha384"
    signature_algorithm: str = "ECDSA-P384"
    key_size: int = 384
```

## Deprecation Policy

### Algorithm Rotation Process

When cryptographic algorithms need to be updated:

1. **Announcement**: Minimum 12-month notice before deprecating an algorithm
2. **Dual support**: New algorithm suite deployed alongside existing
3. **Migration period**: Evidence created with old algorithms remains verifiable
4. **Verification material retention**: Old public keys and certificates retained per REQ-H02
5. **Retirement**: Old algorithm suite retired after migration period

### Transition Periods

| Phase | Duration | Actions |
|-------|----------|---------|
| Announcement | Month 0 | New algorithm suite announced |
| Preparation | Months 1-6 | New keys generated, dual signing available |
| Migration | Months 7-12 | Default switches to new algorithms |
| Grace period | Months 13-18 | Old algorithms still supported for verification |
| Retirement | Month 18+ | Old algorithms removed from new signatures |

### Key Rotation Schedule

| Key Type | Rotation Frequency | Notes |
|----------|-------------------|-------|
| Signing key | Every 2 years or on compromise | Certificate validity |
| Timestamping key | Every 2 years or on compromise | Certificate validity |
| KEK | Annually or on compromise | Master encryption key |
| DEK | Per-object | One-time use |

### Triggering Events for Emergency Rotation

- Suspected or confirmed key compromise
- Discovery of algorithm weakness
- Regulatory requirement change
- Audit finding requiring remediation

## Qualification Considerations

### Non-Qualified Mode (Current)

In non-qualified mode:
- Software keys stored encrypted at rest
- All outputs clearly labeled as `non_qualified`
- Suitable for development and testing only

### Qualified Mode (Future)

For qualified operation per REQ-D04:
- Keys must be stored in certified HSM via PKCS#11
- No software key fallback permitted
- Fail-closed behavior if HSM unavailable

## Code References

| Component | File Path |
|-----------|-----------|
| Crypto configuration | `src/qerds/core/config.py` (CryptoSettings) |
| Content encryption | `src/qerds/services/encryption.py` |
| Signing and timestamping | `src/qerds/services/trust.py` |
| Algorithm suite definition | `src/qerds/services/trust.py` (AlgorithmSuite) |

## Audit Checklist

For conformity assessment, verify:

- [ ] AES-256-GCM used for all content encryption
- [ ] SHA-384 used for evidence hashing
- [ ] ECDSA P-384 used for signing
- [ ] 96-bit nonces generated per GCM operation
- [ ] CSPRNGs used for all key/nonce generation
- [ ] Key sizes meet minimum requirements
- [ ] Algorithm suite version tracked in evidence
- [ ] Qualification label matches operational mode
